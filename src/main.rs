use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use clap::{Args, Parser};
use serde::Deserialize;
use sev::certs::snp::{Chain, Verifiable};
use sev::firmware::guest::AttestationReport;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    json_file: std::path::PathBuf,
    #[command(flatten)]
    exclusive: Exclusive,
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
struct Exclusive {
    #[arg(long)]
    report_data: Option<String>,
    #[arg(long)]
    b64_report_data: Option<String>,
}

mod b64 {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        BASE64_STANDARD
            .decode(base64.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Deserialize)]
pub struct JsonReport {
    /// ATTESTATION_REPORT Structure defined in Table 21 of SEV-SNP firmware ABI specification
    #[serde(with = "b64")]
    pub attestation: Vec<u8>,
    /// Concatenation of VCEK, ASK, and ARK certificates (PEM format, in that order).
    /// <https://www.amd.com/en/support/tech-docs/versioned-chip-endorsement-key-vcek-certificate-and-kds-interface-specification>
    pub platform_certificates: String,
    // UVM Endorsement (UVM reference info)
    // This is a base64 encoded COSE_Sign1 envelope whose issuer and feed should match Confidential ACIs signing identity
    // The payload is a json file containing two fields:
    // - x-ms-sevsnpvm-guestsvn
    //   This is a version number of the Utility VM that the container is running on.
    // - x-ms-sevsnpvm-measurement
    //   This is the SHA256 hash of the Utility VM's measurement. It should match the MEASUREMENT field in the attestation report
    #[serde(with = "b64")]
    pub uvm_endorsements: Vec<u8>,
}

fn main() {
    let args = Cli::parse();

    let content = std::fs::read_to_string(&args.json_file).expect("No such file or directory");
    let json_report = serde_json::from_str::<JsonReport>(&content).expect("Not a valid report");
    let pems = pem::parse_many(json_report.platform_certificates).expect("Not a list of PEMs");
    let (vcek, ask, ark) = (pems[0].clone(), pems[1].clone(), pems[2].clone());

    let chain = Chain::from_der(ark.contents(), ask.contents(), vcek.contents())
        .expect("Unexpected chain of trust");
    let report = AttestationReport::from_bytes(&json_report.attestation).unwrap();

    let expected_report_data = if let Some(b64_report_data) = args.exclusive.b64_report_data {
        Some(
            BASE64_STANDARD
                .decode(b64_report_data)
                .expect("Can't decode args --b64-report-data"),
        )
    } else {
        args.exclusive
            .report_data
            .map(|report_data| hex::decode(report_data).expect("Can't decode args --report-data"))
    };

    let report_data = report.report_data.as_ref();

    if let Some(expected_report_data) = expected_report_data {
        if report_data != expected_report_data {
            panic!(
                "Bad REPORT_DATA, found {}, expected: {}",
                hex::encode(report_data),
                hex::encode(expected_report_data)
            );
        }

        println!("[ OK ] Matching REPORT_DATA");
    }

    (&chain, &report)
        .verify()
        .expect("Failed to verify certificate chain and attestation report");
    println!("[ OK ] Verification of certification chain and attestation report")
}

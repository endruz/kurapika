use std::fmt;
use std::io;
use std::process::Command;

pub struct AuthInfo {
    app_name: String,
    customer_name: String,
    deploy_date: String,
    expire_date: String,
    base_board_id: String,
    cpu_id: String,
    // gpu_id: Vec<String>,
}

impl AuthInfo {
    pub fn new(
        app_name: String,
        customer_name: String,
        deploy_date: String,
        expire_date: String,
    ) -> AuthInfo {
        let base_board_id = get_base_board_id().unwrap();
        let cpu_id = get_cpu_id().unwrap();

        AuthInfo {
            app_name,
            customer_name,
            deploy_date,
            expire_date,
            base_board_id,
            cpu_id,
        }
    }
}

impl fmt::Display for AuthInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            r#"{{
    app_name: "{}",
    customer_name: "{}",
    deploy_date: {},
    expire_date: {},
    base_board_id: "{}",
    cpu_id: "{}"
}}"#,
            self.app_name,
            self.customer_name,
            self.deploy_date,
            self.expire_date,
            self.base_board_id,
            self.cpu_id
        )
    }
}

/// 获取 BASE_BOARD_ID
pub fn get_base_board_id() -> Result<String, io::Error> {
    let command: String = "dmidecode -t 2 | grep Serial | awk '{print $3}'".to_string();
    let output = Command::new("sh").arg("-c").arg(command).output()?;
    let base_board_id: String = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(base_board_id)
}

/// 获取 CPU_ID
pub fn get_cpu_id() -> Result<String, io::Error> {
    let command: String = "dmidecode -t 4 | grep ID |sort -u |awk -F': ' '{print $2}'".to_string();
    let output = Command::new("sh").arg("-c").arg(command).output()?;
    let cpu_id: String = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(cpu_id)
}

/// 获取 GPU_ID
pub fn get_gpu_id() -> Result<Vec<String>, io::Error> {
    let command: String = "lspci | grep -i nvidia | awk '{print $1}'".to_string();
    let output = Command::new("sh").arg("-c").arg(command).output()?;
    let gpu_id: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .to_string()
        .split_whitespace()
        .map(String::from)
        .collect();
    Ok(gpu_id)
}

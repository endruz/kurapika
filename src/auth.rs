// Std
use std::fmt;
use std::process::Command;

// External
use chrono::{Local, NaiveDate};
use serde::Deserialize;

// Internal
use crate::error::KurapikaError;

#[derive(Deserialize)]
pub struct AuthInfo {
    app_name: String,
    customer_name: String,
    deploy_date: String,
    expire_date: String,
    base_board_id: String,
    cpu_id: String,
}

impl AuthInfo {
    pub fn new(
        app_name: String,
        customer_name: String,
        deploy_date: String,
        expire_date: String,
    ) -> Result<AuthInfo, KurapikaError> {
        let base_board_id = get_base_board_id()?;
        let cpu_id = get_cpu_id()?;

        Ok(AuthInfo {
            app_name,
            customer_name,
            deploy_date,
            expire_date,
            base_board_id,
            cpu_id,
        })
    }

    pub fn from_str(s: &str) -> Result<AuthInfo, KurapikaError> {
        match toml::from_str::<AuthInfo>(s) {
            Ok(auth_info) => Ok(auth_info),
            Err(_) => Err(KurapikaError::ParseFailure),
        }
    }

    pub fn verify(&self) -> Result<(), KurapikaError> {
        // 验证 BASE_BOARD_ID
        if self.base_board_id != get_base_board_id()? {
            return Err(KurapikaError::VerifyFailure);
        }
        // 验证 CPU_ID
        if self.cpu_id != get_cpu_id()? {
            return Err(KurapikaError::VerifyFailure);
        }
        // 验证部署时间和过期时间
        let now = Local::now().date_naive();
        let deploy_date = match NaiveDate::parse_from_str(&self.deploy_date, "%Y-%m-%d") {
            Ok(date) => date,
            Err(_) => return Err(KurapikaError::VerifyFailure),
        };
        let expire_date = match NaiveDate::parse_from_str(&self.expire_date, "%Y-%m-%d") {
            Ok(date) => date,
            Err(_) => return Err(KurapikaError::VerifyFailure),
        };
        if deploy_date > now || now >= expire_date {
            return Err(KurapikaError::VerifyFailure);
        }

        Ok(())
    }
}

impl fmt::Display for AuthInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            r#"app_name = "{}"
customer_name = "{}"
deploy_date = "{}"
expire_date = "{}"
base_board_id = "{}"
cpu_id = "{}""#,
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
fn get_base_board_id() -> Result<String, KurapikaError> {
    const GET_BASE_BOARD_ID_CMD: &str = "dmidecode -t 2 | grep Serial | awk '{print $3}'";
    execute_cmd(GET_BASE_BOARD_ID_CMD)
}

/// 获取 CPU_ID
fn get_cpu_id() -> Result<String, KurapikaError> {
    const GET_CPU_ID_CMD: &str = "dmidecode -t 4 | grep ID |sort -u |awk -F': ' '{print $2}'";
    execute_cmd(GET_CPU_ID_CMD)
}

/// 执行命令
fn execute_cmd(cmd: &str) -> Result<String, KurapikaError> {
    let output = match Command::new("sh").arg("-c").arg(cmd).output() {
        Ok(out) => out,
        Err(_) => return Err(KurapikaError::ParseFailure),
    };
    let base_board_id: String = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(base_board_id)
}

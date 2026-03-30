use airlock_controller::crd::{AirlockChamber, AirlockTool};
use kube::CustomResourceExt;

fn main() {
    print!("{}", serde_yaml::to_string(&AirlockChamber::crd()).unwrap());
    println!("---");
    print!("{}", serde_yaml::to_string(&AirlockTool::crd()).unwrap());
}

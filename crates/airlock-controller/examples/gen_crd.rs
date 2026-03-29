use airlock_controller::crd::AirlockTool;
use kube::CustomResourceExt;

fn main() {
    print!("{}", serde_yaml::to_string(&AirlockTool::crd()).unwrap());
}

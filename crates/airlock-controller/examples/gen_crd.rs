use airlock_controller::crd::AirlockChamber;
use kube::CustomResourceExt;

fn main() {
    print!("{}", serde_yaml::to_string(&AirlockChamber::crd()).unwrap());
}

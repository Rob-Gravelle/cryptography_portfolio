import json

def save_wheel_config(machine, filename):
    """Save the wheel bits and positions of a LorenzMachine to a JSON file."""
    config = {
        "chi": [{"bits": w.bits, "position": w.position} for w in machine.chi_wheels],
        "psi": [{"bits": w.bits, "position": w.position} for w in machine.psi_wheels],
        "mu":  [{"bits": w.bits, "position": w.position} for w in machine.mu_wheels],
    }
    with open(filename, 'w') as f:
        json.dump(config, f, indent=2)

def load_wheel_config(machine, filename):
    """Load wheel bits and positions from a JSON file into an existing LorenzMachine."""
    with open(filename, 'r') as f:
        config = json.load(f)

    for wheels, data in zip(
        [machine.chi_wheels, machine.psi_wheels, machine.mu_wheels],
        [config["chi"], config["psi"], config["mu"]]
    ):
        for w, saved in zip(wheels, data):
            w.bits = saved["bits"]
            w.position = saved["position"]
# (Optional) Save/load wheel configuration

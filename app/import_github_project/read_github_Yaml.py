import yaml

def parse_yaml_rules(filepath):
    """
    Parses a YAML file containing one or more security rules.

    :param filepath: Path to the YAML file.
    :return: List of dictionaries, each representing a rule.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            rules = yaml.safe_load(file)
            if not isinstance(rules, list):
                raise ValueError("The YAML file must contain a list of rules.")
            return rules
    except Exception as e:
        print(f"Error parsing YAML file: {e}")
        return []

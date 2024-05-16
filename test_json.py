import json

file = open('output.json', 'r')

file_json = json.load(file)

rules = file_json['rules']

for rule_key, rule_item in rules.items():
    print(f"- Capability: {rule_key}")

    if len(rule_item['meta']['attack']) > 0:
        for attack in rule_item['meta']['attack']:
            print(f"-- ATT&CK Tactic: {attack['tactic']}, ATT&CK Technique: {attack['technique']}")

    if len(rule_item['meta']['mbc']) > 0:
        for mbc in rule_item['meta']['mbc']:
            print(f"-- MBC Objective: {mbc['objective']}, MBC Behavior: {mbc['behavior']}")
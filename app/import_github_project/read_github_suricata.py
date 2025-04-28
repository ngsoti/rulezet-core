from pyparsing import Word, nums, alphas, oneOf, Suppress, Group, ZeroOrMore, restOfLine, CharsNotIn

def parse_rule_suricata():
    # Définition des éléments de la règle
    action = oneOf("alert drop reject pass")
    proto = oneOf("tcp udp icmp ip http tls dns")
    ip_addr = Word(nums + "./:$") | "any"
    port = Word(nums) | "any"
    direction = oneOf("-> <>")

    # Définir les options entre parenthèses
    option_name = Word(alphas + "_")
    option_value = CharsNotIn(";")  # <-- stop at ;
    option = Group(option_name + Suppress(":") + option_value + Suppress(";"))
    options = Suppress("(") + ZeroOrMore(option) + Suppress(")")

    # Construction complète de la règle
    rule = (
        action("action")
        + proto("proto")
        + ip_addr("src_ip")
        + port("src_port")
        + direction("direction")
        + ip_addr("dst_ip")
        + port("dst_port")
        + options("options")
    )
    
    return rule

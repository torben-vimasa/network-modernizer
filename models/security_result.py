from models.acl_match import ACLMatch


class SecurityResult:

    def __init__(self):
        self.permitted = False
        self.rule = None
        self.match: ACLMatch | None = None
        self.reason = ""
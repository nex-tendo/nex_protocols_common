from nintendo.nex import rmc, kerberos, authentication, common
import secrets
from pymongo.collection import Collection


class AuthenticationUser:
    def __init__(self, pid, name, password):
        self.pid = pid
        self.name = name
        self.password = password


class CommonAuthenticationServer(authentication.AuthenticationServer):
    def __init__(self,
                 settings,
                 secure_host: str,
                 secure_port: int,
                 build_string: str,
                 special_users: list[AuthenticationUser],
                 nexaccounts_db: Collection):

        super().__init__()
        self.settings = settings

        self.special_users = special_users
        self.secure_host = secure_host
        self.secure_port = secure_port
        self.build_string = build_string
        self.nexaccounts_db = nexaccounts_db

    # ============= Utility functions  =============

    def derive_key(self, user: AuthenticationUser):
        deriv = kerberos.KeyDerivationOld(65000, 1024)
        return deriv.derive_key(user.password.encode("ascii"), user.pid)

    def generate_ticket(self, source: AuthenticationUser, target: AuthenticationUser):
        user_key = self.derive_key(source)
        server_key = self.derive_key(target)
        session_key = secrets.token_bytes(self.settings["kerberos.key_size"])

        internal = kerberos.ServerTicket()
        internal.timestamp = common.DateTime.now()
        internal.source = source.pid
        internal.session_key = session_key

        ticket = kerberos.ClientTicket()
        ticket.session_key = session_key
        ticket.target = target.pid
        ticket.internal = internal.encrypt(server_key, self.settings)

        return ticket.encrypt(user_key, self.settings)

    def get_special_user(self, pid: int):
        for u in self.special_users:
            if u.pid == pid:
                return u

    def get_user_from_pid(self, pid: int):
        user = self.nexaccounts_db.find_one({"pid": pid})
        if user:
            return AuthenticationUser(user["pid"], str(user["pid"]), user["password"])
        return user

    # ============= Method implementations  =============

    async def login(self, client, username):
        print("User trying to log in:", username)

        user = self.get_user_from_pid(int(username))
        if not user:
            raise common.RMCError("RendezVous::InvalidUsername")

        server = self.get_special_user(2)  # Special user: Quazal Rendez-Vous
        if not server:
            print("No special users with PID 2 ... fix this please!")
            raise common.RMCError("Core::NotImplemented")

        url = common.StationURL(
            scheme="prudps", address=self.secure_host, port=self.secure_port,
            PID=server.pid, CID=1, type=2,
            sid=1, stream=10
        )

        conn_data = authentication.RVConnectionData()
        conn_data.main_station = url
        conn_data.special_protocols = []
        conn_data.special_station = common.StationURL()
        conn_data.server_time = common.DateTime.now()

        response = rmc.RMCResponse()
        response.result = common.Result.success()
        response.pid = user.pid
        response.ticket = self.generate_ticket(user, server)
        response.connection_data = conn_data
        response.server_name = self.build_string
        return response

    # Wii U servers don't seem to check what's in the extra data.
    async def login_ex(self, client, username, extra_data):
        print("User trying to log in:", username)

        user = self.get_user_from_pid(int(username))
        if not user:
            raise common.RMCError("RendezVous::InvalidUsername")

        server = self.get_special_user(pid=2)  # Special user: Quazal Rendez-Vous
        if not server:
            print("No special users with PID 2 ... fix this please!")
            raise common.RMCError("Core::NotImplemented")

        url = common.StationURL(
            scheme="prudps", address=self.secure_host, port=self.secure_port,
            PID=server.pid, CID=1, type=2,
            sid=1, stream=10
        )

        conn_data = authentication.RVConnectionData()
        conn_data.main_station = url
        conn_data.special_protocols = []
        conn_data.special_station = common.StationURL()
        conn_data.server_time = common.DateTime.now()

        response = rmc.RMCResponse()
        response.result = common.Result.success()
        response.pid = user.pid
        response.ticket = self.generate_ticket(user, server)
        response.connection_data = conn_data
        response.server_name = self.build_string
        return response

    async def request_ticket(self, client, source, target):
        print("User trying to request ticket:", source, target)

        user = self.get_user_from_pid(source)
        if not user:
            raise common.RMCError("Core::AccessDenied")

        server = self.get_special_user(target)  # Special user: Quazal Rendez-Vous
        if not server:
            raise common.RMCError("Core::AccessDenied")

        response = rmc.RMCResponse()
        response.result = common.Result.success()
        response.ticket = self.generate_ticket(user, server)
        return response

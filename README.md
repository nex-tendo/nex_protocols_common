# NEX common protocols in Python

- These are designed to work on the WiiU and 3DS, switch specific features were discarded

# Usage

You may need:

- S3 instance
- MongoDB server 6.0+
- Redis server 7.0+

Install Python3 and these libs:

- [NintendoClients](https://github.com/kinnay/NintendoClients)
- ``python -m pip install aioconsole requests pymongo redis grpcio-tools boto3``

# Common to all protocols

- [**Example MK8 server**](https://github.com/EpicUsername12/nex_mario_kart_8)

Assuming you're running a MK8 server: (change based on your)

```py
from nintendo.nex import settings

GAME_SERVER_ID = 0x1010EB00
ACCESS_KEY = "25dbf96a"
NEX_VERSION = 30504

# NEX_SETTINGS = settings.load("friends")
NEX_SETTINGS = settings.default()
NEX_SETTINGS.configure(ACCESS_KEY, NEX_VERSION)
NEX_SETTINGS["prudp.resend_timeout"] = 1.5
NEX_SETTINGS["prudp.resend_limit"] = 3
NEX_SETTINGS["prudp.version"] = 1
NEX_SETTINGS["prudp.max_substream_id"] = 1
```

## Authentication Protocol (authentication server)

- Implements both Login/LoginEx
- Doesn't check the NEX token in LoginEx

Example usage:

```py

account_grpc_client = grpc.insecure_channel('%s:%d' % ("localhost", 50051))
account_service = account_service_pb2_grpc.AccountStub(account_grpc_client)

SecureServerUser = AuthenticationUser(2, "Quazal Rendez-Vous", "EPIC_SECURE_AUTH_PASS") # make the password actually secure
GuestUser = AuthenticationUser(100, "guest", "MMQea3n!fsik")

def example_get_nex_password(pid: int) -> str:
    response = account_service.GetNEXPassword(GetNEXPasswordRequest(pid=pid), metadata=[("x-api-key", "GRPC_API_KEY")])
    return response.password


def example_auth_callback(auth_user: AuthenticationUser) -> common.Result:
    if is_maintenance:
        return common.Result.error("Authentication::UnderMaintenance")
    return common.Result.success()

AuthenticationServer = CommonAuthenticationServer(
    NEX_SETTINGS,
    secure_host="124.124.56.111", # Your external IPv4 address
    secure_port=1224, # Secure server is open on port 1224
    build_string="Example-BUILD-string-22cef", # Build string
    special_users=[SecureServerUser, GuestUser], # You can remove the Guest users
    get_nex_password_func=example_get_nex_password, # Callback: The function that will fetch user NEX passwords
    auth_callback=example_auth_callback # Callback: The function that will be called on each login attempt (you can raise RMC exceptions)
)
```

## Secure Connecition Protocol (secure server)

- Basic secure connection protocol, doesn't decrypt and decompress secure reports.

Example usage:

```py
SecureConnectionServer = CommonSecureConnectionServer(
    NEX_SETTINGS,
    sessions_db=session_collection, # The MongoDB collection that will store user session URLs
    reportdata_db=reportdata_collection # The MongoDB collection that will store secure report data (unused yet)
)
```

## Ranking Protocol (secure server)

- Implements rankings using Redis and MongoDB
- Standard (1224) and Ordinal rankings (1234) are supported
- Self, global, and around self rankings are implemented

Example usage:

```py
redis_client = redis.from_url("redis://127.0.0.1:6379")
redis_client.ping()

RankingServer = CommonRankingServer(
    NEX_SETTINGS,
    rankings_db=ranking_scores_collection,
    redis_instance=redis_client,
    commondata_db=ranking_commondata_collection,
    common_data_handler=None, # Optional, look MK8 to see how it can be used
    rankings_category={} # Ranking categories if you want some of them to be Ascending, other descending (dict[int, int])
)                          
```

## Matchmake Extension Protocol (secure server)

- Basic matchmake extension protocol, you can add additional filters to your matchmaking find requests (see MK8 server)

Example usage:

```py
MatchmakeExtensionServer = CommonMatchmakeExtensionServer(
    NEX_SETTINGS,
    gatherings_db=gatherings_collection,
    sequence_db=sequence_collection,
    get_friend_pids_func=example_get_friend_pids_func,
    secure_connection_server=SecureConnectionServer
)                       
```

## Matchmaking Ext Protocol (secure server)

Example usage:

```py
MatchmakingExtServer = CommonMatchMakingServerExt(
    NEX_SETTINGS,
    gatherings_db=gatherings_collection,
    sequence_db=sequence_collection
)
```

## NAT Traversal Protocol (secure server)

- Doesn't check the NAT traversal result data, should be used so the users isn't put in the same gathering every time

Example usage:

```py
NATTraversalServer = CommonNATTraversalServer(
    NEX_SETTINGS,
    sessions_db=session_collection,
    secure_connection_server=SecureConnectionServer
)
```

## Matchmaking Protocol (secure server)

Example usage:

```py
MatchmakingServer = CommonMatchMakingServer(
    NEX_SETTINGS,
    gatherings_db=gatherings_collection,
    sessions_db=session_collection,
    sequence_db=sequence_collection                                            
)
```

## DataStore Protocol (secure server)

- Bad code, but works well!

Example usage:

```py
s3_client = boto3.client(
    's3',
    region_name="us-east-1",
    endpoint_url="https://s3.endpoint.change.to.yourendpoint",
    aws_access_key_id="s3_access_key",
    aws_secret_access_key="s3_secret",
    config=Config(signature_version='s3v4') # Required for presigned POST
)

def example_calculate_s3_object_key_ex(database, pid, persistence_id: int, object_id: int) -> str:
    if persistence_id < 1024:
        return "ghosts/%d/%d.bin" % (pid, persistence_id)
    else:
        return "mktv/%d.bin" % (object_id)

def example_calculate_s3_object_key(database, client, persistence_id: int, object_id: int) -> str:
    if persistence_id < 1024:
        return "ghosts/%d/%d.bin" % (client.pid(), persistence_id)
    else:
        return "mktv/%d.bin" % (object_id)

def example_head_object_by_key(key: str) -> tuple[bool, int, str]:
    url = "https://%s.b-cdn.net/%s" % ("example-bucket.yourCDNdomain", key)
    res = requests.head(url)
    success = (res.status_code == 200)
    return success, (0 if not success else int(res.headers["Content-Length"])), url

DataStoreServer = MK8DataStoreServer(
    NEX_SETTINGS,
    s3_client=s3_client,
    s3_endpoint_domain="https://s3.endpoint.change.to.yourendpoint",
    s3_bucket="your_s3_bucket_name",
    datastore_db=datastore_collection,
    sequence_db=sequence_collection,
    head_object_by_key=example_head_object_by_key, # Callback: Get success, size, url by object key
    calculate_s3_object_key=example_calculate_s3_object_key, # Callback: Get object key by client, persistence id, object id
    calculate_s3_object_key_ex=example_calculate_s3_object_key_ex # Callback: Get object key by PID, persistence id, object id
)
```
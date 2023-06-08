from nintendo.nex import rmc, common, matchmaking
from pymongo.collection import Collection

from . import matchmaking_utils


class CommonMatchMakingServerExt(matchmaking.MatchMakingServerExt):
    def __init__(self,
                 settings,
                 gatherings_db: Collection,
                 sequence_db: Collection):

        super().__init__()
        self.settings = settings
        self.gatherings_db = gatherings_db
        self.sequence_db = sequence_db

    async def logout(self, client):
        gatherings = list(self.gatherings_db.find({"players": {"$in": [client.pid()]}}))
        print("Removing disconnected player %d from %d gatherings ... " % (client.pid(), len(gatherings)))
        for gathering in gatherings:
            matchmaking_utils.remove_user_from_gathering_ex(self.gatherings_db, client, gathering, "")

    # ============= Utility functions  =============

    # ============= Method implementations  =============

    async def end_participation(self, client, gid, message):

        if len(message) > 256:
            raise common.RMCError("Core::InvalidArgument")

        matchmaking_utils.remove_user_from_gathering(self.gatherings_db, client, gid, message)
        return True

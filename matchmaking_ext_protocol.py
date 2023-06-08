from nintendo.nex import rmc, common, matchmaking
from pymongo.collection import Collection

from . import matchmaking_utils


class GatheringFlags:
    MIGRATE_OWNERSHIP = 0x10
    LEAVE_PERSISTENT_GATHERING_ON_DISCONNECT = 0x40
    ALLOW_ZERO_PARTICIPANT = 0x80
    CAN_OWNERSHIP_BE_TAKEN_BY_PARTICIPANTS = 0x200
    SEND_NOTIFICATIONS_ON_PARTICIPATION = 0x400
    SEND_NOTIFICATIONS_ON_PARTICIPATION = 0x800


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
            res = matchmaking_utils.remove_user_from_gathering_ex(self.gatherings_db, client, gathering, "")
            self.do_gathering_update_logic(client, res)

    # ============= Utility functions  =============

    def do_gathering_update_logic(self, client, gathering):
        if gathering["type"] == "PersistentGathering":
            if len(gathering["players"]) == 0:
                if gathering["flags"] & GatheringFlags.ALLOW_ZERO_PARTICIPANT:
                    pass
                else:
                    self.gatherings_db.delete_one({"id": gathering["id"]})
        else:
            if len(gathering["players"]) == 0:
                self.gatherings_db.delete_one({"id": gathering["id"]})
            elif client.pid() == gathering["owner"]:
                # Update owner if the old one disconnected
                # TODO: Trigger notifications ...
                self.gatherings_db.update_one({"id": gathering["id"]}, {"$set": {
                    "owner": gathering["players"][0]
                }})

    # ============= Method implementations  =============

    async def end_participation(self, client, gid, message):

        if len(message) > 256:
            raise common.RMCError("Core::InvalidArgument")

        res = matchmaking_utils.remove_user_from_gathering(self.gatherings_db, client, gid, message)
        self.do_gathering_update_logic(client, res)

        return True

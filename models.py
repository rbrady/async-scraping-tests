from pydantic import BaseModel
from typing import List, Any, Dict, Optional
import ujson


class PVulnerability(BaseModel):
    """
    Class representing the record to be returned. Uses strange capitalization
    to be backwards compatible in the json output with previous version of feed data.
    """
    Name: str
    NamespaceName: str
    Description: str
    Severity: str
    Metadata: Dict = None
    Link: str
    FixedIn: Optional[List[Any]] = []

    class Config:
        json_loads = ujson.loads
        json_dumps = ujson.dumps


class PFixedIn(BaseModel):
    """
    Class representing a fix record for return back to the service from the driver. The semantics of the version are:
    "None" -> Package is vulnerable and no fix available yet
    ! "None" -> Version of package with a fix for a vulnerability. Assume all older versions of the package are vulnerable.
    """
    Name: str
    NamespaceName: str
    VersionFormat: str
    Version: str

    class Config:
        json_loads = ujson.loads
        json_dumps = ujson.dumps


# original models from amazon driver
# -----------------------------------------
class JsonifierMixin(object):
    def json(self):
        jsonified = {}
        for k, v in vars(self).items():
            if not k[0] == "_":
                if type(v) == list or type(v) == set:
                    jsonified[k] = [
                        x.json() if hasattr(x, "json") and callable(x.json) else x
                        for x in v
                    ]
                elif type(v) == dict:
                    jsonified[k] = {
                        x: y.json() if hasattr(y, "json") and callable(y.json) else y
                        for x, y in v.items()
                    }
                else:
                    if hasattr(v, "json"):
                        jsonified[k] = v.json()
                    else:
                        jsonified[k] = v
        return jsonified


class Vulnerability(JsonifierMixin):
    """
    Class representing the record to be returned. Uses strange capitalization
    to be backwards compatible in the json output with previous version of feed data.
    """

    def __init__(self):
        self.Name = None
        self.NamespaceName = None
        self.Description = ""
        self.Severity = None
        self.Metadata = None
        self.Link = None
        self.FixedIn = []


class FixedIn(JsonifierMixin):
    """
    Class representing a fix record for return back to the service from the driver. The semantics of the version are:
    "None" -> Package is vulnerable and no fix available yet
    ! "None" -> Version of package with a fix for a vulnerability. Assume all older versions of the package are vulnerable.
    """

    def __init__(self):
        self.Name = None
        self.NamespaceName = None
        self.VersionFormat = None
        self.Version = None

# ----------------------------------------

"""The CrowdStrike Falcon OAuth2 API SDK endpoints module (Minimal version).

 @@@@@@@  @@@@@@@    @@@@@@   @@@  @@@  @@@  @@@@@@@    @@@@@@   @@@@@@@  @@@@@@@   @@@  @@@  @@@  @@@@@@@@
@@@@@@@@  @@@@@@@@  @@@@@@@@  @@@  @@@  @@@  @@@@@@@@  @@@@@@@   @@@@@@@  @@@@@@@@  @@@  @@@  @@@  @@@@@@@@
!@@       @@!  @@@  @@!  @@@  @@!  @@!  @@!  @@!  @@@  !@@         @@!    @@!  @@@  @@!  @@!  !@@  @@!
!@!       !@!  @!@  !@!  @!@  !@!  !@!  !@!  !@!  @!@  !@!         !@!    !@!  @!@  !@!  !@!  @!!  !@!
!@!       @!@!!@!   @!@  !@!  @!!  !!@  @!@  @!@  !@!  !!@@!!      @!!    @!@!!@!   !!@  @!@@!@!   @!!!:!
!!!       !!@!@!    !@!  !!!  !@!  !!!  !@!  !@!  !!!   !!@!!!     !!!    !!@!@!    !!!  !!@!!!    !!!!!:
:!!       !!: :!!   !!:  !!!  !!:  !!:  !!:  !!:  !!!       !:!    !!:    !!: :!!   !!:  !!: :!!   !!:
:!:       :!:  !:!  :!:  !:!  :!:  :!:  :!:  :!:  !:!      !:!     :!:    :!:  !:!  :!:  :!:  !:!  :!:
 ::: :::  ::   :::  ::::: ::   :::: :: :::    :::: ::  :::: ::      ::    ::   :::   ::   ::  :::   :: ::::
 :: :: :   :   : :   : :  :     :: :  : :    :: :  :   :: : :       :      :   : :  :     :   :::  : :: ::

                                                         _______       __                  _______
                                                        |   _   .---.-|  .----.-----.-----|   _   .--.--.
                                                        |.  1___|  _  |  |  __|  _  |     |.  1   |  |  |
                                                        |.  __) |___._|__|____|_____|__|__|.  ____|___  |
                                                        |:  |                             |:  |   |_____|
                                                        |::.|     CrowdStrike Falcon      |::.|
                                                        `---' OAuth2 API SDK for Python 3 `---'
"""
from typing import List, Any

from ._alerts import _alerts_endpoints
from ._prevention_policies import _prevention_policies_endpoints
from ._oauth2 import _oauth2_endpoints

api_endpoints: List[Any] = []
api_endpoints.extend(_alerts_endpoints)
api_endpoints.extend(_prevention_policies_endpoints)
api_endpoints.extend(_oauth2_endpoints)

# Deprecated endpoints (empty for minimal version)
deprecated_endpoints = []

# Operation deprecation mapping (empty for minimal version)
operation_deprecation_mapping = {}

# Class deprecation mapping (empty for minimal version)
class_deprecation_mapping = {}
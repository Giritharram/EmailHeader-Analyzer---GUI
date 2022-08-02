import imp


import re
import imp

txt = "Received: from BL2PRD0711HT001.namprd07.prod.outlook.com (10.255.104.164) by BY2PRD0711HT003.namprd07.prod.outlook.com (10.255.88.166) with Microsoft SMTP Server (TLS) id 14.16.257.4; Thu, 17 Jan 2013 23:35:35 +0000"


print(re.split('from |by |with |\n', txt))
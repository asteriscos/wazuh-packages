#!/bin/bash

### Change LEFT MENU Wazuh name to Nokia

# plugins/wazuh/target/public/wazuh.plugin.js
#/home/wazuh/Downloads/packages/wazuh.plugin.js
#


sed -i 's|id:"wazuh",title:"Wazuh"|id:"wazuh",title:"Nokia"|g' ./opensearch-dashboards/wazuh/target/public/wazuh.plugin.js
sed -i 's|category:{id:"wazuh",label:"Wazuh"|category:{id:"wazuh",label:"Nokia"|g' ./opensearch-dashboards/wazuh/target/public/wazuh.plugin.js
sed -i 's|"Wazuh dashboard"|"Nokia dashboard"|g' ./opensearch-dashboards/wazuh/target/public/wazuh.plugin.js
gzip -c ./opensearch-dashboards/wazuh/target/public/wazuh.plugin.js > ./opensearch-dashboards/wazuh/target/public/wazuh.plugin.js.gz
brotli -c ./opensearch-dashboards/wazuh/target/public/wazuh.plugin.js > ./opensearch-dashboards/wazuh/target/public/wazuh.plugin.js.br


# plugins/wazuh/target/public/wazuh.chunk.10.js
# /home/wazuh/Downloads/packages/wazuh.chunk.10.js

### Remove Health Check Wazuh name 
sed -i 's|Check Wazuh API connection|Check server API connection|g' ./opensearch-dashboards/wazuh/target/public/wazuh.chunk.10.js
sed -i 's|Check Wazuh API version|Check server API version|g' ./opensearch-dashboards/wazuh/target/public/wazuh.chunk.10.js

sed -i 's|Wazuh API seems to be down|Server API seems to be down|g' ./opensearch-dashboards/wazuh/target/public/wazuh.chunk.10.js
sed -i 's|Check the Wazuh API service status|Check the server API service status|g' ./opensearch-dashboards/wazuh/target/public/wazuh.chunk.10.js

### Change tab title and breadcrumb name
sed -i 's|chrome\.docTitle\.change("Wazuh"\.concat(pageTitleSuffix));|chrome.docTitle.change("Dashboards".concat(pageTitleSuffix));|g' ./opensearch-dashboards/wazuh/target/public/wazuh.chunk.10.js
sed -i 's|"discover\.discoverBreadcrumbTitle",{defaultMessage:"Wazuh"}|"discover.discoverBreadcrumbTitle",{defaultMessage:"Dashboards"}|g' ./opensearch-dashboards/wazuh/target/public/wazuh.chunk.10.js

### Change Wazuh API title in Settings section
sed -i 's|Wazuh API configuration|Server API configuration|g' ./opensearch-dashboards/wazuh/target/public/wazuh.chunk.10.js

gzip -c ./opensearch-dashboards/wazuh/target/public/wazuh.chunk.10.js > ./opensearch-dashboards/wazuh/target/public/wazuh.chunk.10.js.gz
brotli -c ./opensearch-dashboards/wazuh/target/public/wazuh.chunk.10.js > ./opensearch-dashboards/wazuh/target/public/wazuh.chunk.10.js.br

# "Check Wazuh API version"
# "Check server API version"
# "Wazuh API seems to be down"
# "Server API seems to be down"

# " server can reach the configured Wazuh API"
# " Already configured Wazuh API(s)"

zip -r ./packages/nokia-custom-wazuh-4.4.3-1.zip ./opensearch-dashboards
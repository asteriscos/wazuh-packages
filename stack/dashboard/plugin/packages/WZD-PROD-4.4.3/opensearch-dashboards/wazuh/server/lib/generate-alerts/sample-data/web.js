"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.userAgents = exports.urls = exports.data = exports.Protocols = void 0;

/*
 * Wazuh app - Docker sample data
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const Protocols = ['GET'];
exports.Protocols = Protocols;
const urls = ['/', '/index.asp', '/remote/login?lang=en', '/index.php?lang=en', '/phpmyadmin2020/index.php?lang=en', '/pma2020/index.php?lang=en', '/administrator/admin/index.php?lang=en', '	/administrator/pma/index.php?lang=en', '/administrator/db/index.php?lang=en', '/db/phpMyAdmin-3/index.php?lang=en', '/db/myadmin/index.php?lang=en', '/sql/phpMyAdmin/index.php?lang=en', '/sql/phpmyadmin2/index.php?lang=en', '/sql/sqlweb/index.php?lang=en', '/mysql/web/index.php?lang=en', '/wp-content/plugins/portable-phpmyadmin/wp-pma-mod/index.php?lang=en', '/shopdb/index.php?lang=en'];
exports.urls = urls;
const userAgents = [// https://deviceatlas.com/blog/list-of-user-agent-strings
// Desktop 
'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246', 'Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9', 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36', // Smartphones
'Mozilla/5.0 (Linux; Android 8.0.0; SM-G960F Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.84 Mobile Safari/537.36', 'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 6P Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.83 Mobile Safari/537.36', 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1', 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/69.0.3497.105 Mobile/15E148 Safari/605.1', 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1', 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A5370a Safari/604.1', // Tablets 
'Mozilla/5.0 (Linux; Android 7.0; Pixel C Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.98 Safari/537.36', 'Mozilla/5.0 (Linux; Android 6.0.1; SGP771 Build/32.2.A.0.253; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.98 Safari/537.36', 'Mozilla/5.0 (Linux; Android 6.0.1; SHIELD Tablet K1 Build/MRA58K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/55.0.2883.91 Safari/537.36', 'Mozilla/5.0 (Linux; Android 7.0; SM-T827R4 Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.116 Safari/537.36', 'Mozilla/5.0 (Linux; Android 5.0.2; LG-V410/V41020c Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/34.0.1847.118 Safari/537.36', // Mobile browsers
'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_1 like Mac OS X) AppleWebKit/603.1.30 (KHTML, like Gecko) Version/10.0 Mobile/14E304 Safari/602.1', 'Mozilla/5.0 (Linux; U; Android 4.4.2; en-us; SCH-I535 Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30', 'Mozilla/5.0 (Linux; Android 7.0; SM-G930V Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.125 Mobile Safari/537.36', 'Mozilla/5.0 (Linux; Android 7.0; SM-A310F Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.91 Mobile Safari/537.36 OPR/42.7.2246.114996', 'Mozilla/5.0 (Android 7.0; Mobile; rv:54.0) Gecko/54.0 Firefox/54.0', 'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_2 like Mac OS X) AppleWebKit/603.2.4 (KHTML, like Gecko) FxiOS/7.5b3349 Mobile/14F89 Safari/603.2.4', 'Mozilla/5.0 (Linux; Android 7.0; SAMSUNG SM-G955U Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/5.4 Chrome/51.0.2704.106 Mobile Safari/537.36', 'Mozilla/5.0 (Linux; U; Android 7.0; en-us; MI 5 Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/53.0.2785.146 Mobile Safari/537.36 XiaoMi/MiuiBrowser/9.0.3', // Consoles
'Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30 (KHTML, like Gecko) NX/3.0.4.2.12 NintendoBrowser/4.3.1.11264.US', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; XBOX_ONE_ED) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393', 'Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge/13.10586', 'Mozilla/5.0 (PlayStation 4 3.11) AppleWebKit/537.73 (KHTML, like Gecko)', 'Mozilla/5.0 (PlayStation Vita 3.61) AppleWebKit/537.73 (KHTML, like Gecko) Silk/3.2', 'Mozilla/5.0 (Nintendo 3DS; U; ; en) Version/1.7412.EU'];
exports.userAgents = userAgents;
const data = [{
  "rule": {
    "firedtimes": 6,
    "mail": false,
    "level": 5,
    "pci_dss": ["6.5", "11.4"],
    "description": "Web server 400 error code.",
    "groups": ["web", "accesslog", "attack"],
    "id": "31101",
    "nist_800_53": ["SA.11", "SI.4"],
    "gdpr": ["IV_35.7.d"]
  },
  "location": "/var/log/httpd/access_log",
  "decoder": {
    "name": "web-accesslog"
  },
  "full_log": "{data.srcip} - - [{_date}] \"{data.protocol} {data.url} HTTP/1.1\" {data.id} 219 \"-\" \"{_user_agent}\""
}, {
  "previous_output": "94.111.43.1 - - [24/Apr/2020:07:34:21 +0000] \"GET /phpmyadmin2019/index.php?lang=en HTTP/1.1\" 404 222 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36\"\n94.111.43.1 - - [24/Apr/2020:07:34:20 +0000] \"GET /phpmyadmin2018/index.php?lang=en HTTP/1.1\" 404 222 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36\"\n94.111.43.1 - - [24/Apr/2020:07:34:20 +0000] \"GET /phpmyadmin2017/index.php?lang=en HTTP/1.1\" 404 222 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36\"\n94.111.43.1 - - [24/Apr/2020:07:34:19 +0000] \"GET /phpmyadmin2016/index.php?lang=en HTTP/1.1\" 404 222 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36\"\n94.111.43.1 - - [24/Apr/2020:07:34:19 +0000] \"GET /phpmyadmin2015/index.php?lang=en HTTP/1.1\" 404 222 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36\"\n94.111.43.1 - - [24/Apr/2020:07:34:19 +0000] \"GET /phpmyadmin2014/index.php?lang=en HTTP/1.1\" 404 222 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36\"\n94.111.43.1 - - [24/Apr/2020:07:34:19 +0000] \"GET /phpmyadmin2013/index.php?lang=en HTTP/1.1\" 404 222 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36\"\n94.111.43.1 - - [24/Apr/2020:07:34:18 +0000] \"GET /phpmyadmin2012/index.php?lang=en HTTP/1.1\" 404 222 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36\"\n94.111.43.1 - - [24/Apr/2020:07:34:18 +0000] \"GET /phpmyadmin2011/index.php?lang=en HTTP/1.1\" 404 222 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36\"\n94.111.43.1 - - [24/Apr/2020:07:34:17 +0000] \"GET /pma2020/index.php?lang=en HTTP/1.1\" 404 215 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36\"\n94.111.43.1 - - [24/Apr/2020:07:34:17 +0000] \"GET /pma2019/index.php?lang=en HTTP/1.1\" 404 215 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36\"",
  // "data": {
  //   "protocol": "GET",
  //   "srcip": "94.111.43.1",
  //   "id": "404",
  //   "url": "/phpmyadmin2020/index.php?lang=en"
  // },
  "rule": {
    "firedtimes": 8,
    "mail": false,
    "level": 10,
    "pci_dss": ["6.5", "11.4"],
    "description": "Multiple web server 400 error codes from same source ip.",
    "groups": ["web", "accesslog", "web_scan", "recon"],
    "id": "31151",
    "nist_800_53": ["SA.11", "SI.4"],
    "frequency": 14,
    "gdpr": ["IV_35.7.d"]
  },
  "decoder": {
    "name": "web-accesslog"
  },
  "full_log": "{data.srcip} - - [{_date}] \"{data.protocol} {data.url} HTTP/1.1\" {data.id} 222 \"-\" \"{_user_agent}\"",
  "location": "/var/log/httpd/access_log"
}];
exports.data = data;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndlYi5qcyJdLCJuYW1lcyI6WyJQcm90b2NvbHMiLCJ1cmxzIiwidXNlckFnZW50cyIsImRhdGEiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBRU8sTUFBTUEsU0FBUyxHQUFHLENBQUMsS0FBRCxDQUFsQjs7QUFFQSxNQUFNQyxJQUFJLEdBQUcsQ0FBQyxHQUFELEVBQU0sWUFBTixFQUFvQix1QkFBcEIsRUFBNkMsb0JBQTdDLEVBQW1FLG1DQUFuRSxFQUF3Ryw0QkFBeEcsRUFBc0ksd0NBQXRJLEVBQWdMLHVDQUFoTCxFQUF5TixxQ0FBek4sRUFBZ1Esb0NBQWhRLEVBQ3BCLCtCQURvQixFQUNhLG1DQURiLEVBQ2tELG9DQURsRCxFQUN3RiwrQkFEeEYsRUFDeUgsOEJBRHpILEVBQ3lKLHNFQUR6SixFQUNpTywyQkFEak8sQ0FBYjs7QUFJQSxNQUFNQyxVQUFVLEdBQUcsQ0FBRTtBQUMxQjtBQUNBLGdGQUZ3QixFQUd4QixpSUFId0IsRUFJeEIsbUhBSndCLEVBS3hCLHNIQUx3QixFQU14QiwrR0FOd0IsRUFReEI7QUFDQSwwSUFUd0IsRUFVeEIsMklBVndCLEVBV3hCLHlJQVh3QixFQVl4QixnSkFad0IsRUFheEIseUlBYndCLEVBY3hCLDJJQWR3QixFQWdCeEI7QUFDQSxpSkFqQndCLEVBa0J4Qix3SkFsQndCLEVBbUJ4Qiw0SkFuQndCLEVBb0J4QixvSUFwQndCLEVBcUJ4Qix3SkFyQndCLEVBdUJ4QjtBQUNBLDJJQXhCd0IsRUF5QnhCLDZJQXpCd0IsRUEwQnhCLDBJQTFCd0IsRUEyQnhCLDhKQTNCd0IsRUE0QnhCLG9FQTVCd0IsRUE2QnhCLDZJQTdCd0IsRUE4QnhCLHFLQTlCd0IsRUErQnhCLHFMQS9Cd0IsRUFpQ3hCO0FBQ0EsaUhBbEN3QixFQW1DeEIsK0lBbkN3QixFQW9DeEIsOEpBcEN3QixFQXFDeEIseUVBckN3QixFQXNDeEIscUZBdEN3QixFQXVDeEIsdURBdkN3QixDQUFuQjs7QUEwQ0EsTUFBTUMsSUFBSSxHQUFHLENBQ2xCO0FBQ0UsVUFBUTtBQUNOLGtCQUFjLENBRFI7QUFFTixZQUFRLEtBRkY7QUFHTixhQUFTLENBSEg7QUFJTixlQUFXLENBQUMsS0FBRCxFQUFPLE1BQVAsQ0FKTDtBQUtOLG1CQUFlLDRCQUxUO0FBTU4sY0FBVSxDQUFDLEtBQUQsRUFBTyxXQUFQLEVBQW1CLFFBQW5CLENBTko7QUFPTixVQUFNLE9BUEE7QUFRTixtQkFBZSxDQUFDLE9BQUQsRUFBUyxNQUFULENBUlQ7QUFTTixZQUFRLENBQUMsV0FBRDtBQVRGLEdBRFY7QUFZRSxjQUFZLDJCQVpkO0FBYUUsYUFBVztBQUNULFlBQVE7QUFEQyxHQWJiO0FBZ0JFLGNBQVk7QUFoQmQsQ0FEa0IsRUFtQmxCO0FBQ0UscUJBQW1CLCs5RUFEckI7QUFFRTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxVQUFRO0FBQ04sa0JBQWMsQ0FEUjtBQUVOLFlBQVEsS0FGRjtBQUdOLGFBQVMsRUFISDtBQUlOLGVBQVcsQ0FBQyxLQUFELEVBQU8sTUFBUCxDQUpMO0FBS04sbUJBQWUsMERBTFQ7QUFNTixjQUFVLENBQUMsS0FBRCxFQUFPLFdBQVAsRUFBbUIsVUFBbkIsRUFBOEIsT0FBOUIsQ0FOSjtBQU9OLFVBQU0sT0FQQTtBQVFOLG1CQUFlLENBQUMsT0FBRCxFQUFTLE1BQVQsQ0FSVDtBQVNOLGlCQUFhLEVBVFA7QUFVTixZQUFRLENBQUMsV0FBRDtBQVZGLEdBUlY7QUFvQkUsYUFBVztBQUNULFlBQVE7QUFEQyxHQXBCYjtBQXVCRSxjQUFZLDBHQXZCZDtBQXdCRSxjQUFZO0FBeEJkLENBbkJrQixDQUFiIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIERvY2tlciBzYW1wbGUgZGF0YVxuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cblxuZXhwb3J0IGNvbnN0IFByb3RvY29scyA9IFsnR0VUJ107XG5cbmV4cG9ydCBjb25zdCB1cmxzID0gWycvJywgJy9pbmRleC5hc3AnLCAnL3JlbW90ZS9sb2dpbj9sYW5nPWVuJywgJy9pbmRleC5waHA/bGFuZz1lbicsICcvcGhwbXlhZG1pbjIwMjAvaW5kZXgucGhwP2xhbmc9ZW4nLCAnL3BtYTIwMjAvaW5kZXgucGhwP2xhbmc9ZW4nLCAnL2FkbWluaXN0cmF0b3IvYWRtaW4vaW5kZXgucGhwP2xhbmc9ZW4nLCAnXHQvYWRtaW5pc3RyYXRvci9wbWEvaW5kZXgucGhwP2xhbmc9ZW4nLCAnL2FkbWluaXN0cmF0b3IvZGIvaW5kZXgucGhwP2xhbmc9ZW4nLCAnL2RiL3BocE15QWRtaW4tMy9pbmRleC5waHA/bGFuZz1lbicsXG4nL2RiL215YWRtaW4vaW5kZXgucGhwP2xhbmc9ZW4nLCAnL3NxbC9waHBNeUFkbWluL2luZGV4LnBocD9sYW5nPWVuJywgJy9zcWwvcGhwbXlhZG1pbjIvaW5kZXgucGhwP2xhbmc9ZW4nLCAnL3NxbC9zcWx3ZWIvaW5kZXgucGhwP2xhbmc9ZW4nLCAnL215c3FsL3dlYi9pbmRleC5waHA/bGFuZz1lbicsICcvd3AtY29udGVudC9wbHVnaW5zL3BvcnRhYmxlLXBocG15YWRtaW4vd3AtcG1hLW1vZC9pbmRleC5waHA/bGFuZz1lbicsICcvc2hvcGRiL2luZGV4LnBocD9sYW5nPWVuJ11cblxuXG5leHBvcnQgY29uc3QgdXNlckFnZW50cyA9IFsgLy8gaHR0cHM6Ly9kZXZpY2VhdGxhcy5jb20vYmxvZy9saXN0LW9mLXVzZXItYWdlbnQtc3RyaW5nc1xuICAvLyBEZXNrdG9wIFxuICAnTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NDsgcnY6NTcuMCkgR2Vja28vMjAxMDAxMDEgRmlyZWZveC81Ny4wJyxcbiAgJ01vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS80Mi4wLjIzMTEuMTM1IFNhZmFyaS81MzcuMzYgRWRnZS8xMi4yNDYnLFxuICAnTW96aWxsYS81LjAgKFgxMTsgQ3JPUyB4ODZfNjQgODE3Mi40NS4wKSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvNTEuMC4yNzA0LjY0IFNhZmFyaS81MzcuMzYnLFxuICAnTW96aWxsYS81LjAgKE1hY2ludG9zaDsgSW50ZWwgTWFjIE9TIFggMTBfMTFfMikgQXBwbGVXZWJLaXQvNjAxLjMuOSAoS0hUTUwsIGxpa2UgR2Vja28pIFZlcnNpb24vOS4wLjIgU2FmYXJpLzYwMS4zLjknLFxuICAnTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgNi4xOyBXT1c2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzQ3LjAuMjUyNi4xMTEgU2FmYXJpLzUzNy4zNicsXG5cbiAgLy8gU21hcnRwaG9uZXNcbiAgJ01vemlsbGEvNS4wIChMaW51eDsgQW5kcm9pZCA4LjAuMDsgU00tRzk2MEYgQnVpbGQvUjE2TlcpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS82Mi4wLjMyMDIuODQgTW9iaWxlIFNhZmFyaS81MzcuMzYnICxcbiAgJ01vemlsbGEvNS4wIChMaW51eDsgQW5kcm9pZCA2LjAuMTsgTmV4dXMgNlAgQnVpbGQvTU1CMjlQKSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvNDcuMC4yNTI2LjgzIE1vYmlsZSBTYWZhcmkvNTM3LjM2JyxcbiAgJ01vemlsbGEvNS4wIChpUGhvbmU7IENQVSBpUGhvbmUgT1MgMTFfMCBsaWtlIE1hYyBPUyBYKSBBcHBsZVdlYktpdC82MDQuMS4zOCAoS0hUTUwsIGxpa2UgR2Vja28pIFZlcnNpb24vMTEuMCBNb2JpbGUvMTVBMzcyIFNhZmFyaS82MDQuMScsXG4gICdNb3ppbGxhLzUuMCAoaVBob25lOyBDUFUgaVBob25lIE9TIDEyXzAgbGlrZSBNYWMgT1MgWCkgQXBwbGVXZWJLaXQvNjA1LjEuMTUgKEtIVE1MLCBsaWtlIEdlY2tvKSBDcmlPUy82OS4wLjM0OTcuMTA1IE1vYmlsZS8xNUUxNDggU2FmYXJpLzYwNS4xJyxcbiAgJ01vemlsbGEvNS4wIChpUGhvbmU7IENQVSBpUGhvbmUgT1MgMTJfMCBsaWtlIE1hYyBPUyBYKSBBcHBsZVdlYktpdC82MDUuMS4xNSAoS0hUTUwsIGxpa2UgR2Vja28pIFZlcnNpb24vMTIuMCBNb2JpbGUvMTVFMTQ4IFNhZmFyaS82MDQuMScsXG4gICdNb3ppbGxhLzUuMCAoaVBob25lOyBDUFUgaVBob25lIE9TIDExXzAgbGlrZSBNYWMgT1MgWCkgQXBwbGVXZWJLaXQvNjA0LjEuMzggKEtIVE1MLCBsaWtlIEdlY2tvKSBWZXJzaW9uLzExLjAgTW9iaWxlLzE1QTUzNzBhIFNhZmFyaS82MDQuMScsXG5cbiAgLy8gVGFibGV0cyBcbiAgJ01vemlsbGEvNS4wIChMaW51eDsgQW5kcm9pZCA3LjA7IFBpeGVsIEMgQnVpbGQvTlJEOTBNOyB3dikgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgVmVyc2lvbi80LjAgQ2hyb21lLzUyLjAuMjc0My45OCBTYWZhcmkvNTM3LjM2JyxcbiAgJ01vemlsbGEvNS4wIChMaW51eDsgQW5kcm9pZCA2LjAuMTsgU0dQNzcxIEJ1aWxkLzMyLjIuQS4wLjI1Mzsgd3YpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIFZlcnNpb24vNC4wIENocm9tZS81Mi4wLjI3NDMuOTggU2FmYXJpLzUzNy4zNicsXG4gICdNb3ppbGxhLzUuMCAoTGludXg7IEFuZHJvaWQgNi4wLjE7IFNISUVMRCBUYWJsZXQgSzEgQnVpbGQvTVJBNThLOyB3dikgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgVmVyc2lvbi80LjAgQ2hyb21lLzU1LjAuMjg4My45MSBTYWZhcmkvNTM3LjM2JyxcbiAgJ01vemlsbGEvNS4wIChMaW51eDsgQW5kcm9pZCA3LjA7IFNNLVQ4MjdSNCBCdWlsZC9OUkQ5ME0pIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS82MC4wLjMxMTIuMTE2IFNhZmFyaS81MzcuMzYnLFxuICAnTW96aWxsYS81LjAgKExpbnV4OyBBbmRyb2lkIDUuMC4yOyBMRy1WNDEwL1Y0MTAyMGMgQnVpbGQvTFJYMjJHKSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBWZXJzaW9uLzQuMCBDaHJvbWUvMzQuMC4xODQ3LjExOCBTYWZhcmkvNTM3LjM2JyxcblxuICAvLyBNb2JpbGUgYnJvd3NlcnNcbiAgJ01vemlsbGEvNS4wIChpUGhvbmU7IENQVSBpUGhvbmUgT1MgMTBfM18xIGxpa2UgTWFjIE9TIFgpIEFwcGxlV2ViS2l0LzYwMy4xLjMwIChLSFRNTCwgbGlrZSBHZWNrbykgVmVyc2lvbi8xMC4wIE1vYmlsZS8xNEUzMDQgU2FmYXJpLzYwMi4xJyxcbiAgJ01vemlsbGEvNS4wIChMaW51eDsgVTsgQW5kcm9pZCA0LjQuMjsgZW4tdXM7IFNDSC1JNTM1IEJ1aWxkL0tPVDQ5SCkgQXBwbGVXZWJLaXQvNTM0LjMwIChLSFRNTCwgbGlrZSBHZWNrbykgVmVyc2lvbi80LjAgTW9iaWxlIFNhZmFyaS81MzQuMzAnLFxuICAnTW96aWxsYS81LjAgKExpbnV4OyBBbmRyb2lkIDcuMDsgU00tRzkzMFYgQnVpbGQvTlJEOTBNKSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvNTkuMC4zMDcxLjEyNSBNb2JpbGUgU2FmYXJpLzUzNy4zNicsXG4gICdNb3ppbGxhLzUuMCAoTGludXg7IEFuZHJvaWQgNy4wOyBTTS1BMzEwRiBCdWlsZC9OUkQ5ME0pIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS81NS4wLjI4ODMuOTEgTW9iaWxlIFNhZmFyaS81MzcuMzYgT1BSLzQyLjcuMjI0Ni4xMTQ5OTYnLFxuICAnTW96aWxsYS81LjAgKEFuZHJvaWQgNy4wOyBNb2JpbGU7IHJ2OjU0LjApIEdlY2tvLzU0LjAgRmlyZWZveC81NC4wJyxcbiAgJ01vemlsbGEvNS4wIChpUGhvbmU7IENQVSBpUGhvbmUgT1MgMTBfM18yIGxpa2UgTWFjIE9TIFgpIEFwcGxlV2ViS2l0LzYwMy4yLjQgKEtIVE1MLCBsaWtlIEdlY2tvKSBGeGlPUy83LjViMzM0OSBNb2JpbGUvMTRGODkgU2FmYXJpLzYwMy4yLjQnLFxuICAnTW96aWxsYS81LjAgKExpbnV4OyBBbmRyb2lkIDcuMDsgU0FNU1VORyBTTS1HOTU1VSBCdWlsZC9OUkQ5ME0pIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIFNhbXN1bmdCcm93c2VyLzUuNCBDaHJvbWUvNTEuMC4yNzA0LjEwNiBNb2JpbGUgU2FmYXJpLzUzNy4zNicsXG4gICdNb3ppbGxhLzUuMCAoTGludXg7IFU7IEFuZHJvaWQgNy4wOyBlbi11czsgTUkgNSBCdWlsZC9OUkQ5ME0pIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIFZlcnNpb24vNC4wIENocm9tZS81My4wLjI3ODUuMTQ2IE1vYmlsZSBTYWZhcmkvNTM3LjM2IFhpYW9NaS9NaXVpQnJvd3Nlci85LjAuMycsXG5cbiAgLy8gQ29uc29sZXNcbiAgJ01vemlsbGEvNS4wIChOaW50ZW5kbyBXaWlVKSBBcHBsZVdlYktpdC81MzYuMzAgKEtIVE1MLCBsaWtlIEdlY2tvKSBOWC8zLjAuNC4yLjEyIE5pbnRlbmRvQnJvd3Nlci80LjMuMS4xMTI2NC5VUycsXG4gICdNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0OyBYQk9YX09ORV9FRCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzUxLjAuMjcwNC43OSBTYWZhcmkvNTM3LjM2IEVkZ2UvMTQuMTQzOTMnLFxuICAnTW96aWxsYS81LjAgKFdpbmRvd3MgUGhvbmUgMTAuMDsgQW5kcm9pZCA0LjIuMTsgWGJveDsgWGJveCBPbmUpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS80Ni4wLjI0ODYuMCBNb2JpbGUgU2FmYXJpLzUzNy4zNiBFZGdlLzEzLjEwNTg2JyxcbiAgJ01vemlsbGEvNS4wIChQbGF5U3RhdGlvbiA0IDMuMTEpIEFwcGxlV2ViS2l0LzUzNy43MyAoS0hUTUwsIGxpa2UgR2Vja28pJyxcbiAgJ01vemlsbGEvNS4wIChQbGF5U3RhdGlvbiBWaXRhIDMuNjEpIEFwcGxlV2ViS2l0LzUzNy43MyAoS0hUTUwsIGxpa2UgR2Vja28pIFNpbGsvMy4yJyxcbiAgJ01vemlsbGEvNS4wIChOaW50ZW5kbyAzRFM7IFU7IDsgZW4pIFZlcnNpb24vMS43NDEyLkVVJ1xuXTtcblxuZXhwb3J0IGNvbnN0IGRhdGEgPSBbXG4gIHtcbiAgICBcInJ1bGVcIjoge1xuICAgICAgXCJmaXJlZHRpbWVzXCI6IDYsXG4gICAgICBcIm1haWxcIjogZmFsc2UsXG4gICAgICBcImxldmVsXCI6IDUsXG4gICAgICBcInBjaV9kc3NcIjogW1wiNi41XCIsXCIxMS40XCJdLFxuICAgICAgXCJkZXNjcmlwdGlvblwiOiBcIldlYiBzZXJ2ZXIgNDAwIGVycm9yIGNvZGUuXCIsXG4gICAgICBcImdyb3Vwc1wiOiBbXCJ3ZWJcIixcImFjY2Vzc2xvZ1wiLFwiYXR0YWNrXCJdLFxuICAgICAgXCJpZFwiOiBcIjMxMTAxXCIsXG4gICAgICBcIm5pc3RfODAwXzUzXCI6IFtcIlNBLjExXCIsXCJTSS40XCJdLFxuICAgICAgXCJnZHByXCI6IFtcIklWXzM1LjcuZFwiXVxuICAgIH0sXG4gICAgXCJsb2NhdGlvblwiOiBcIi92YXIvbG9nL2h0dHBkL2FjY2Vzc19sb2dcIixcbiAgICBcImRlY29kZXJcIjoge1xuICAgICAgXCJuYW1lXCI6IFwid2ViLWFjY2Vzc2xvZ1wiXG4gICAgfSxcbiAgICBcImZ1bGxfbG9nXCI6IFwie2RhdGEuc3JjaXB9IC0gLSBbe19kYXRlfV0gXFxcIntkYXRhLnByb3RvY29sfSB7ZGF0YS51cmx9IEhUVFAvMS4xXFxcIiB7ZGF0YS5pZH0gMjE5IFxcXCItXFxcIiBcXFwie191c2VyX2FnZW50fVxcXCJcIixcbiAgfSxcbiAge1xuICAgIFwicHJldmlvdXNfb3V0cHV0XCI6IFwiOTQuMTExLjQzLjEgLSAtIFsyNC9BcHIvMjAyMDowNzozNDoyMSArMDAwMF0gXFxcIkdFVCAvcGhwbXlhZG1pbjIwMTkvaW5kZXgucGhwP2xhbmc9ZW4gSFRUUC8xLjFcXFwiIDQwNCAyMjIgXFxcIi1cXFwiIFxcXCJNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvNzcuMC4zODY1LjEyMCBTYWZhcmkvNTM3LjM2XFxcIlxcbjk0LjExMS40My4xIC0gLSBbMjQvQXByLzIwMjA6MDc6MzQ6MjAgKzAwMDBdIFxcXCJHRVQgL3BocG15YWRtaW4yMDE4L2luZGV4LnBocD9sYW5nPWVuIEhUVFAvMS4xXFxcIiA0MDQgMjIyIFxcXCItXFxcIiBcXFwiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzc3LjAuMzg2NS4xMjAgU2FmYXJpLzUzNy4zNlxcXCJcXG45NC4xMTEuNDMuMSAtIC0gWzI0L0Fwci8yMDIwOjA3OjM0OjIwICswMDAwXSBcXFwiR0VUIC9waHBteWFkbWluMjAxNy9pbmRleC5waHA/bGFuZz1lbiBIVFRQLzEuMVxcXCIgNDA0IDIyMiBcXFwiLVxcXCIgXFxcIk1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS83Ny4wLjM4NjUuMTIwIFNhZmFyaS81MzcuMzZcXFwiXFxuOTQuMTExLjQzLjEgLSAtIFsyNC9BcHIvMjAyMDowNzozNDoxOSArMDAwMF0gXFxcIkdFVCAvcGhwbXlhZG1pbjIwMTYvaW5kZXgucGhwP2xhbmc9ZW4gSFRUUC8xLjFcXFwiIDQwNCAyMjIgXFxcIi1cXFwiIFxcXCJNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvNzcuMC4zODY1LjEyMCBTYWZhcmkvNTM3LjM2XFxcIlxcbjk0LjExMS40My4xIC0gLSBbMjQvQXByLzIwMjA6MDc6MzQ6MTkgKzAwMDBdIFxcXCJHRVQgL3BocG15YWRtaW4yMDE1L2luZGV4LnBocD9sYW5nPWVuIEhUVFAvMS4xXFxcIiA0MDQgMjIyIFxcXCItXFxcIiBcXFwiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzc3LjAuMzg2NS4xMjAgU2FmYXJpLzUzNy4zNlxcXCJcXG45NC4xMTEuNDMuMSAtIC0gWzI0L0Fwci8yMDIwOjA3OjM0OjE5ICswMDAwXSBcXFwiR0VUIC9waHBteWFkbWluMjAxNC9pbmRleC5waHA/bGFuZz1lbiBIVFRQLzEuMVxcXCIgNDA0IDIyMiBcXFwiLVxcXCIgXFxcIk1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS83Ny4wLjM4NjUuMTIwIFNhZmFyaS81MzcuMzZcXFwiXFxuOTQuMTExLjQzLjEgLSAtIFsyNC9BcHIvMjAyMDowNzozNDoxOSArMDAwMF0gXFxcIkdFVCAvcGhwbXlhZG1pbjIwMTMvaW5kZXgucGhwP2xhbmc9ZW4gSFRUUC8xLjFcXFwiIDQwNCAyMjIgXFxcIi1cXFwiIFxcXCJNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvNzcuMC4zODY1LjEyMCBTYWZhcmkvNTM3LjM2XFxcIlxcbjk0LjExMS40My4xIC0gLSBbMjQvQXByLzIwMjA6MDc6MzQ6MTggKzAwMDBdIFxcXCJHRVQgL3BocG15YWRtaW4yMDEyL2luZGV4LnBocD9sYW5nPWVuIEhUVFAvMS4xXFxcIiA0MDQgMjIyIFxcXCItXFxcIiBcXFwiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzc3LjAuMzg2NS4xMjAgU2FmYXJpLzUzNy4zNlxcXCJcXG45NC4xMTEuNDMuMSAtIC0gWzI0L0Fwci8yMDIwOjA3OjM0OjE4ICswMDAwXSBcXFwiR0VUIC9waHBteWFkbWluMjAxMS9pbmRleC5waHA/bGFuZz1lbiBIVFRQLzEuMVxcXCIgNDA0IDIyMiBcXFwiLVxcXCIgXFxcIk1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS83Ny4wLjM4NjUuMTIwIFNhZmFyaS81MzcuMzZcXFwiXFxuOTQuMTExLjQzLjEgLSAtIFsyNC9BcHIvMjAyMDowNzozNDoxNyArMDAwMF0gXFxcIkdFVCAvcG1hMjAyMC9pbmRleC5waHA/bGFuZz1lbiBIVFRQLzEuMVxcXCIgNDA0IDIxNSBcXFwiLVxcXCIgXFxcIk1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS83Ny4wLjM4NjUuMTIwIFNhZmFyaS81MzcuMzZcXFwiXFxuOTQuMTExLjQzLjEgLSAtIFsyNC9BcHIvMjAyMDowNzozNDoxNyArMDAwMF0gXFxcIkdFVCAvcG1hMjAxOS9pbmRleC5waHA/bGFuZz1lbiBIVFRQLzEuMVxcXCIgNDA0IDIxNSBcXFwiLVxcXCIgXFxcIk1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS83Ny4wLjM4NjUuMTIwIFNhZmFyaS81MzcuMzZcXFwiXCIsXG4gICAgLy8gXCJkYXRhXCI6IHtcbiAgICAvLyAgIFwicHJvdG9jb2xcIjogXCJHRVRcIixcbiAgICAvLyAgIFwic3JjaXBcIjogXCI5NC4xMTEuNDMuMVwiLFxuICAgIC8vICAgXCJpZFwiOiBcIjQwNFwiLFxuICAgIC8vICAgXCJ1cmxcIjogXCIvcGhwbXlhZG1pbjIwMjAvaW5kZXgucGhwP2xhbmc9ZW5cIlxuICAgIC8vIH0sXG4gICAgXCJydWxlXCI6IHtcbiAgICAgIFwiZmlyZWR0aW1lc1wiOiA4LFxuICAgICAgXCJtYWlsXCI6IGZhbHNlLFxuICAgICAgXCJsZXZlbFwiOiAxMCxcbiAgICAgIFwicGNpX2Rzc1wiOiBbXCI2LjVcIixcIjExLjRcIl0sXG4gICAgICBcImRlc2NyaXB0aW9uXCI6IFwiTXVsdGlwbGUgd2ViIHNlcnZlciA0MDAgZXJyb3IgY29kZXMgZnJvbSBzYW1lIHNvdXJjZSBpcC5cIixcbiAgICAgIFwiZ3JvdXBzXCI6IFtcIndlYlwiLFwiYWNjZXNzbG9nXCIsXCJ3ZWJfc2NhblwiLFwicmVjb25cIl0sXG4gICAgICBcImlkXCI6IFwiMzExNTFcIixcbiAgICAgIFwibmlzdF84MDBfNTNcIjogW1wiU0EuMTFcIixcIlNJLjRcIl0sXG4gICAgICBcImZyZXF1ZW5jeVwiOiAxNCxcbiAgICAgIFwiZ2RwclwiOiBbXCJJVl8zNS43LmRcIl1cbiAgICB9LFxuICAgIFwiZGVjb2RlclwiOiB7XG4gICAgICBcIm5hbWVcIjogXCJ3ZWItYWNjZXNzbG9nXCJcbiAgICB9LFxuICAgIFwiZnVsbF9sb2dcIjogXCJ7ZGF0YS5zcmNpcH0gLSAtIFt7X2RhdGV9XSBcXFwie2RhdGEucHJvdG9jb2x9IHtkYXRhLnVybH0gSFRUUC8xLjFcXFwiIHtkYXRhLmlkfSAyMjIgXFxcIi1cXFwiIFxcXCJ7X3VzZXJfYWdlbnR9XFxcIlwiLFxuICAgIFwibG9jYXRpb25cIjogXCIvdmFyL2xvZy9odHRwZC9hY2Nlc3NfbG9nXCIsXG4gIH1cbl0iXX0=
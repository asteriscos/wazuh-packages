"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for PCI requirements (Reporting)
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
var _default = {
  '1.1.1': 'A formal process for approving and testing all network connections and changes to the firewall and router configurations',
  '1.3.4': 'Do not allow unauthorized outbound traffic from the cardholder data environment to the Internet.',
  '1.4': {
    stack: ['Install personal firewall software or equivalent functionality on any portable computing devices (including company and/or employee-owned) that connect to the Internet when outside the network (for example, laptops used by employees), and which are also used to access the CDE. Firewall (or equivalent) configurations include:', {
      text: '\n'
    }, {
      ul: ['Specific configuration settings are defined.', 'Personal firewall (or equivalent functionality) is actively running.', 'Personal firewall (or equivalent functionality) is not alterable by users of the portable computing devices.']
    }]
  },
  '2.2': 'Develop configuration standards for all system components. Assure that these standards address all known security vulnerabilities and are consistent with industry accepted system hardening standards (CIS, ISO, SANS, NIST).',
  '2.2.2': 'Enable only necessary services, protocols, daemons, etc., as required for the function of the system. ',
  '2.2.3': 'Implement additional security features for any required services, protocols, or daemons that are considered to be insecure',
  '2.2.4': 'Configure system security parameters to prevent misuse.',
  '4.1': {
    stack: ['Use strong cryptography and security protocols (for example, SSL/TLS, IPSEC, SSH, etc.) to safeguard sensitive cardholder data during transmission over open, public networks, including the following:', {
      text: '\n'
    }, {
      ul: ['Only trusted keys and certificates are accepted.', 'The protocol in use only supports secure versions or configurations.', 'The encryption strength is appropriate for the encryption methodology in use.']
    }]
  },
  '5.1': 'Deploy anti-virus software on all systems commonly affected by malicious software (particularly personal computers and servers).',
  '5.2': {
    stack: ['Ensure that all anti-virus mechanisms are maintained as follows:', {
      text: '\n'
    }, {
      ul: ['Are kept current.', 'Perform periodic scans.', 'Generate audit logs which are retained per PCI DSS Requirement 10.7.']
    }]
  },
  '6.2': 'Ensure that all system components and software are protected from known vulnerabilities by installing applicable vendor-supplied security patches. Install critical security patches within one month of release.',
  '6.5': {
    stack: ['Address common coding vulnerabilities in software development processes as follows:', {
      text: '\n'
    }, {
      ul: ['Train developers in secure coding techniques, including how to avoid common coding vulnerabilities, and understanding how sensitive data is handled in memory.', 'Develop applications based on secure coding guidelines.']
    }]
  },
  '6.5.1': 'Injection flaws, particularly SQL injection. Also consider OS Command Injection, LDAP and XPath injection flaws as well as other injection flaws.',
  '6.5.2': 'Buffer overflows',
  '6.5.5': 'Improper error handling',
  '6.5.7': 'Cross-site scripting (XSS)',
  '6.5.8': 'Improper access control (such an insecure direct object references, failure to restrict URL access, directory traversal, and failure to restrict user access to functions).',
  '6.5.10': 'Broken authentication and session management.',
  '6.6': {
    stack: ['For public-facing web applications, address new threats and vulnerabilities on an ongoing basis and ensure these applications are protected against known attacks by either of the following methods:', {
      text: '\n'
    }, {
      ul: ['Reviewing public-facing web applications via manual or automated application vulnerability security assessment tools or methods, at least annually and after any changes', 'Installing an automated technical solution that detects and prevents web-based attacks (for example, a web-application firewall) in front of public-facing web applications, to continually check all traffic.']
    }]
  },
  '8.1.2': 'Control addition, deletion, and modification of user IDs, credentials, and other identifier objects.',
  '8.1.4': 'Remove/disable inactive user accounts within 90 days.',
  '8.1.5': {
    stack: ['Manage IDs used by third parties to access, support, or maintain system components via remote access as follows:', {
      text: '\n'
    }, {
      ul: ['Enabled only during the time period needed and disabled when not in use.', 'Monitored when in use.']
    }]
  },
  '8.1.6': 'Limit repeated access attempts by locking out the user ID after not more than six attempts.',
  '8.1.8': 'If a session has been idle for more than 15 minutes, require the user to reauthenticate to re-activate the terminal or session.',
  '8.2.4': 'Change user passwords/passphrases at least once every 90 days.',
  '8.5.1': 'Additional requirement for service providers: Service providers with remote access to customer premises (for example, for support of POS systems or servers) must use a unique authentication credential (such as a password/phrase) for each customer.',
  '8.7': {
    stack: ['All access to any database containing cardholder data (including access by applications, administrators, and all other users) is restricted as follows:', {
      text: '\n'
    }, {
      ul: ['All user access to, user queries of, and user actions on databases are through programmatic methods.', 'Only database administrators have the ability to directly access or query databases.', 'Application IDs for database applications can only be used by the applications (and not by individual users or other non-application processes).']
    }]
  },
  '10.1': 'Implement audit trails to link all access to system components to each individual user.',
  '10.2.1': 'All individual user accesses to cardholder data',
  '10.2.2': 'All actions taken by any individual with root or administrative privileges.',
  '10.2.4': 'Invalid logical access attempts',
  '10.2.5': 'Use of and changes to identification and authentication mechanisms including but not limited to creation of new accounts and elevation of privileges and all changes, additions, or deletions to accounts with root or administrative privileges.',
  '10.2.6': 'Initialization, stopping, or pausing of the audit logs',
  '10.2.7': 'Creation and deletion of system level objects',
  '10.5.2': 'Protect audit trail files from unauthorized modifications',
  '10.5.5': 'Use file integrity monitoring or change detection software on logs to ensure that existing log data cannot be changed without generating alerts (although new data being added should not cause an alert).',
  '10.4': 'Using time-synchronization technology, synchronize all critical system clocks and times and ensure that the following is implemented for acquiring, distributing, and storing time.',
  '10.6': 'Review logs and security events for all system components to identify anomalies or suspicious activity',
  '10.6.1': {
    stack: ['Review the following at least daily:', {
      text: '\n'
    }, {
      ul: ['All security events.', 'Logs of all system components that store, process, or transmit CHD and/or SAD, or that could impact the security of CHD and/or SAD.', 'Logs of all critical system components.', 'Logs of all servers and system components that perform security functions (for example, firewalls, intrusion detection systems/intrusion prevention systems (IDS/IPS), authentication servers, ecommerce redirection servers, etc.)']
    }],
    style: 'standard'
  },
  '11.4': 'Use intrusion detection and/or intrusion prevention techniques to detect and/or prevent intrusions into the network. Monitor all traffic at the perimeter of the cardholder data environment as well as at critical points in the cardholder data environment, and alert personnel to suspected compromises. Keep all intrusion detection and prevention engines, baselines, and signatures up to date.',
  '11.5': 'Deploy a change detection mechanism (for example, file integrity monitoring tools) to alert personnel to unauthorized modification of critical system files, configuration files, or content files; and configure the software to perform critical file comparisons at least weekly.'
};
exports.default = _default;
module.exports = exports.default;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInBjaS1yZXF1aXJlbWVudHMtcGRmbWFrZS50cyJdLCJuYW1lcyI6WyJzdGFjayIsInRleHQiLCJ1bCIsInN0eWxlIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtlQUNlO0FBQ2IsV0FDRSwwSEFGVztBQUdiLFdBQ0Usa0dBSlc7QUFLYixTQUFPO0FBQ0xBLElBQUFBLEtBQUssRUFBRSxDQUNMLHdVQURLLEVBRUw7QUFBRUMsTUFBQUEsSUFBSSxFQUFFO0FBQVIsS0FGSyxFQUdMO0FBQ0VDLE1BQUFBLEVBQUUsRUFBRSxDQUNGLDhDQURFLEVBRUYsc0VBRkUsRUFHRiw4R0FIRTtBQUROLEtBSEs7QUFERixHQUxNO0FBa0JiLFNBQ0UsZ09BbkJXO0FBb0JiLFdBQ0Usd0dBckJXO0FBc0JiLFdBQ0UsNEhBdkJXO0FBd0JiLFdBQVMseURBeEJJO0FBeUJiLFNBQU87QUFDTEYsSUFBQUEsS0FBSyxFQUFFLENBQ0wseU1BREssRUFFTDtBQUFFQyxNQUFBQSxJQUFJLEVBQUU7QUFBUixLQUZLLEVBR0w7QUFDRUMsTUFBQUEsRUFBRSxFQUFFLENBQ0Ysa0RBREUsRUFFRixzRUFGRSxFQUdGLCtFQUhFO0FBRE4sS0FISztBQURGLEdBekJNO0FBc0NiLFNBQ0Usa0lBdkNXO0FBd0NiLFNBQU87QUFDTEYsSUFBQUEsS0FBSyxFQUFFLENBQ0wsa0VBREssRUFFTDtBQUFFQyxNQUFBQSxJQUFJLEVBQUU7QUFBUixLQUZLLEVBR0w7QUFDRUMsTUFBQUEsRUFBRSxFQUFFLENBQ0YsbUJBREUsRUFFRix5QkFGRSxFQUdGLHNFQUhFO0FBRE4sS0FISztBQURGLEdBeENNO0FBcURiLFNBQ0UsbU5BdERXO0FBdURiLFNBQU87QUFDTEYsSUFBQUEsS0FBSyxFQUFFLENBQ0wscUZBREssRUFFTDtBQUFFQyxNQUFBQSxJQUFJLEVBQUU7QUFBUixLQUZLLEVBR0w7QUFDRUMsTUFBQUEsRUFBRSxFQUFFLENBQ0YsZ0tBREUsRUFFRix5REFGRTtBQUROLEtBSEs7QUFERixHQXZETTtBQW1FYixXQUNFLG1KQXBFVztBQXFFYixXQUFTLGtCQXJFSTtBQXNFYixXQUFTLHlCQXRFSTtBQXVFYixXQUFTLDRCQXZFSTtBQXdFYixXQUNFLDZLQXpFVztBQTBFYixZQUFVLCtDQTFFRztBQTJFYixTQUFPO0FBQ0xGLElBQUFBLEtBQUssRUFBRSxDQUNMLHVNQURLLEVBRUw7QUFBRUMsTUFBQUEsSUFBSSxFQUFFO0FBQVIsS0FGSyxFQUdMO0FBQ0VDLE1BQUFBLEVBQUUsRUFBRSxDQUNGLDBLQURFLEVBRUYsZ05BRkU7QUFETixLQUhLO0FBREYsR0EzRU07QUF1RmIsV0FDRSxzR0F4Rlc7QUF5RmIsV0FBUyx1REF6Rkk7QUEwRmIsV0FBUztBQUNQRixJQUFBQSxLQUFLLEVBQUUsQ0FDTCxrSEFESyxFQUVMO0FBQUVDLE1BQUFBLElBQUksRUFBRTtBQUFSLEtBRkssRUFHTDtBQUNFQyxNQUFBQSxFQUFFLEVBQUUsQ0FDRiwwRUFERSxFQUVGLHdCQUZFO0FBRE4sS0FISztBQURBLEdBMUZJO0FBc0diLFdBQ0UsNkZBdkdXO0FBd0diLFdBQ0UsaUlBekdXO0FBMEdiLFdBQVMsZ0VBMUdJO0FBMkdiLFdBQ0UseVBBNUdXO0FBNkdiLFNBQU87QUFDTEYsSUFBQUEsS0FBSyxFQUFFLENBQ0wseUpBREssRUFFTDtBQUFFQyxNQUFBQSxJQUFJLEVBQUU7QUFBUixLQUZLLEVBR0w7QUFDRUMsTUFBQUEsRUFBRSxFQUFFLENBQ0Ysc0dBREUsRUFFRixzRkFGRSxFQUdGLGtKQUhFO0FBRE4sS0FISztBQURGLEdBN0dNO0FBMEhiLFVBQ0UseUZBM0hXO0FBNEhiLFlBQVUsaURBNUhHO0FBNkhiLFlBQ0UsNkVBOUhXO0FBK0hiLFlBQVUsaUNBL0hHO0FBZ0liLFlBQ0UsbVBBaklXO0FBa0liLFlBQVUsd0RBbElHO0FBbUliLFlBQVUsK0NBbklHO0FBb0liLFlBQVUsMkRBcElHO0FBcUliLFlBQ0UsNE1BdElXO0FBdUliLFVBQ0UscUxBeElXO0FBeUliLFVBQ0Usd0dBMUlXO0FBMkliLFlBQVU7QUFDUkYsSUFBQUEsS0FBSyxFQUFFLENBQ0wsc0NBREssRUFFTDtBQUFFQyxNQUFBQSxJQUFJLEVBQUU7QUFBUixLQUZLLEVBR0w7QUFDRUMsTUFBQUEsRUFBRSxFQUFFLENBQ0Ysc0JBREUsRUFFRixxSUFGRSxFQUdGLHlDQUhFLEVBSUYscU9BSkU7QUFETixLQUhLLENBREM7QUFhUkMsSUFBQUEsS0FBSyxFQUFFO0FBYkMsR0EzSUc7QUEwSmIsVUFDRSx5WUEzSlc7QUE0SmIsVUFDRTtBQTdKVyxDIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIE1vZHVsZSBmb3IgUENJIHJlcXVpcmVtZW50cyAoUmVwb3J0aW5nKVxuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cbmV4cG9ydCBkZWZhdWx0IHtcbiAgJzEuMS4xJzpcbiAgICAnQSBmb3JtYWwgcHJvY2VzcyBmb3IgYXBwcm92aW5nIGFuZCB0ZXN0aW5nIGFsbCBuZXR3b3JrIGNvbm5lY3Rpb25zIGFuZCBjaGFuZ2VzIHRvIHRoZSBmaXJld2FsbCBhbmQgcm91dGVyIGNvbmZpZ3VyYXRpb25zJyxcbiAgJzEuMy40JzpcbiAgICAnRG8gbm90IGFsbG93IHVuYXV0aG9yaXplZCBvdXRib3VuZCB0cmFmZmljIGZyb20gdGhlIGNhcmRob2xkZXIgZGF0YSBlbnZpcm9ubWVudCB0byB0aGUgSW50ZXJuZXQuJyxcbiAgJzEuNCc6IHtcbiAgICBzdGFjazogW1xuICAgICAgJ0luc3RhbGwgcGVyc29uYWwgZmlyZXdhbGwgc29mdHdhcmUgb3IgZXF1aXZhbGVudCBmdW5jdGlvbmFsaXR5IG9uIGFueSBwb3J0YWJsZSBjb21wdXRpbmcgZGV2aWNlcyAoaW5jbHVkaW5nIGNvbXBhbnkgYW5kL29yIGVtcGxveWVlLW93bmVkKSB0aGF0IGNvbm5lY3QgdG8gdGhlIEludGVybmV0IHdoZW4gb3V0c2lkZSB0aGUgbmV0d29yayAoZm9yIGV4YW1wbGUsIGxhcHRvcHMgdXNlZCBieSBlbXBsb3llZXMpLCBhbmQgd2hpY2ggYXJlIGFsc28gdXNlZCB0byBhY2Nlc3MgdGhlIENERS4gRmlyZXdhbGwgKG9yIGVxdWl2YWxlbnQpIGNvbmZpZ3VyYXRpb25zIGluY2x1ZGU6JyxcbiAgICAgIHsgdGV4dDogJ1xcbicgfSxcbiAgICAgIHtcbiAgICAgICAgdWw6IFtcbiAgICAgICAgICAnU3BlY2lmaWMgY29uZmlndXJhdGlvbiBzZXR0aW5ncyBhcmUgZGVmaW5lZC4nLFxuICAgICAgICAgICdQZXJzb25hbCBmaXJld2FsbCAob3IgZXF1aXZhbGVudCBmdW5jdGlvbmFsaXR5KSBpcyBhY3RpdmVseSBydW5uaW5nLicsXG4gICAgICAgICAgJ1BlcnNvbmFsIGZpcmV3YWxsIChvciBlcXVpdmFsZW50IGZ1bmN0aW9uYWxpdHkpIGlzIG5vdCBhbHRlcmFibGUgYnkgdXNlcnMgb2YgdGhlIHBvcnRhYmxlIGNvbXB1dGluZyBkZXZpY2VzLidcbiAgICAgICAgXVxuICAgICAgfVxuICAgIF1cbiAgfSxcbiAgJzIuMic6XG4gICAgJ0RldmVsb3AgY29uZmlndXJhdGlvbiBzdGFuZGFyZHMgZm9yIGFsbCBzeXN0ZW0gY29tcG9uZW50cy4gQXNzdXJlIHRoYXQgdGhlc2Ugc3RhbmRhcmRzIGFkZHJlc3MgYWxsIGtub3duIHNlY3VyaXR5IHZ1bG5lcmFiaWxpdGllcyBhbmQgYXJlIGNvbnNpc3RlbnQgd2l0aCBpbmR1c3RyeSBhY2NlcHRlZCBzeXN0ZW0gaGFyZGVuaW5nIHN0YW5kYXJkcyAoQ0lTLCBJU08sIFNBTlMsIE5JU1QpLicsXG4gICcyLjIuMic6XG4gICAgJ0VuYWJsZSBvbmx5IG5lY2Vzc2FyeSBzZXJ2aWNlcywgcHJvdG9jb2xzLCBkYWVtb25zLCBldGMuLCBhcyByZXF1aXJlZCBmb3IgdGhlIGZ1bmN0aW9uIG9mIHRoZSBzeXN0ZW0uICcsXG4gICcyLjIuMyc6XG4gICAgJ0ltcGxlbWVudCBhZGRpdGlvbmFsIHNlY3VyaXR5IGZlYXR1cmVzIGZvciBhbnkgcmVxdWlyZWQgc2VydmljZXMsIHByb3RvY29scywgb3IgZGFlbW9ucyB0aGF0IGFyZSBjb25zaWRlcmVkIHRvIGJlIGluc2VjdXJlJyxcbiAgJzIuMi40JzogJ0NvbmZpZ3VyZSBzeXN0ZW0gc2VjdXJpdHkgcGFyYW1ldGVycyB0byBwcmV2ZW50IG1pc3VzZS4nLFxuICAnNC4xJzoge1xuICAgIHN0YWNrOiBbXG4gICAgICAnVXNlIHN0cm9uZyBjcnlwdG9ncmFwaHkgYW5kIHNlY3VyaXR5IHByb3RvY29scyAoZm9yIGV4YW1wbGUsIFNTTC9UTFMsIElQU0VDLCBTU0gsIGV0Yy4pIHRvIHNhZmVndWFyZCBzZW5zaXRpdmUgY2FyZGhvbGRlciBkYXRhIGR1cmluZyB0cmFuc21pc3Npb24gb3ZlciBvcGVuLCBwdWJsaWMgbmV0d29ya3MsIGluY2x1ZGluZyB0aGUgZm9sbG93aW5nOicsXG4gICAgICB7IHRleHQ6ICdcXG4nIH0sXG4gICAgICB7XG4gICAgICAgIHVsOiBbXG4gICAgICAgICAgJ09ubHkgdHJ1c3RlZCBrZXlzIGFuZCBjZXJ0aWZpY2F0ZXMgYXJlIGFjY2VwdGVkLicsXG4gICAgICAgICAgJ1RoZSBwcm90b2NvbCBpbiB1c2Ugb25seSBzdXBwb3J0cyBzZWN1cmUgdmVyc2lvbnMgb3IgY29uZmlndXJhdGlvbnMuJyxcbiAgICAgICAgICAnVGhlIGVuY3J5cHRpb24gc3RyZW5ndGggaXMgYXBwcm9wcmlhdGUgZm9yIHRoZSBlbmNyeXB0aW9uIG1ldGhvZG9sb2d5IGluIHVzZS4nXG4gICAgICAgIF1cbiAgICAgIH1cbiAgICBdXG4gIH0sXG4gICc1LjEnOlxuICAgICdEZXBsb3kgYW50aS12aXJ1cyBzb2Z0d2FyZSBvbiBhbGwgc3lzdGVtcyBjb21tb25seSBhZmZlY3RlZCBieSBtYWxpY2lvdXMgc29mdHdhcmUgKHBhcnRpY3VsYXJseSBwZXJzb25hbCBjb21wdXRlcnMgYW5kIHNlcnZlcnMpLicsXG4gICc1LjInOiB7XG4gICAgc3RhY2s6IFtcbiAgICAgICdFbnN1cmUgdGhhdCBhbGwgYW50aS12aXJ1cyBtZWNoYW5pc21zIGFyZSBtYWludGFpbmVkIGFzIGZvbGxvd3M6JyxcbiAgICAgIHsgdGV4dDogJ1xcbicgfSxcbiAgICAgIHtcbiAgICAgICAgdWw6IFtcbiAgICAgICAgICAnQXJlIGtlcHQgY3VycmVudC4nLFxuICAgICAgICAgICdQZXJmb3JtIHBlcmlvZGljIHNjYW5zLicsXG4gICAgICAgICAgJ0dlbmVyYXRlIGF1ZGl0IGxvZ3Mgd2hpY2ggYXJlIHJldGFpbmVkIHBlciBQQ0kgRFNTIFJlcXVpcmVtZW50IDEwLjcuJ1xuICAgICAgICBdXG4gICAgICB9XG4gICAgXVxuICB9LFxuICAnNi4yJzpcbiAgICAnRW5zdXJlIHRoYXQgYWxsIHN5c3RlbSBjb21wb25lbnRzIGFuZCBzb2Z0d2FyZSBhcmUgcHJvdGVjdGVkIGZyb20ga25vd24gdnVsbmVyYWJpbGl0aWVzIGJ5IGluc3RhbGxpbmcgYXBwbGljYWJsZSB2ZW5kb3Itc3VwcGxpZWQgc2VjdXJpdHkgcGF0Y2hlcy4gSW5zdGFsbCBjcml0aWNhbCBzZWN1cml0eSBwYXRjaGVzIHdpdGhpbiBvbmUgbW9udGggb2YgcmVsZWFzZS4nLFxuICAnNi41Jzoge1xuICAgIHN0YWNrOiBbXG4gICAgICAnQWRkcmVzcyBjb21tb24gY29kaW5nIHZ1bG5lcmFiaWxpdGllcyBpbiBzb2Z0d2FyZSBkZXZlbG9wbWVudCBwcm9jZXNzZXMgYXMgZm9sbG93czonLFxuICAgICAgeyB0ZXh0OiAnXFxuJyB9LFxuICAgICAge1xuICAgICAgICB1bDogW1xuICAgICAgICAgICdUcmFpbiBkZXZlbG9wZXJzIGluIHNlY3VyZSBjb2RpbmcgdGVjaG5pcXVlcywgaW5jbHVkaW5nIGhvdyB0byBhdm9pZCBjb21tb24gY29kaW5nIHZ1bG5lcmFiaWxpdGllcywgYW5kIHVuZGVyc3RhbmRpbmcgaG93IHNlbnNpdGl2ZSBkYXRhIGlzIGhhbmRsZWQgaW4gbWVtb3J5LicsXG4gICAgICAgICAgJ0RldmVsb3AgYXBwbGljYXRpb25zIGJhc2VkIG9uIHNlY3VyZSBjb2RpbmcgZ3VpZGVsaW5lcy4nXG4gICAgICAgIF1cbiAgICAgIH1cbiAgICBdXG4gIH0sXG4gICc2LjUuMSc6XG4gICAgJ0luamVjdGlvbiBmbGF3cywgcGFydGljdWxhcmx5IFNRTCBpbmplY3Rpb24uIEFsc28gY29uc2lkZXIgT1MgQ29tbWFuZCBJbmplY3Rpb24sIExEQVAgYW5kIFhQYXRoIGluamVjdGlvbiBmbGF3cyBhcyB3ZWxsIGFzIG90aGVyIGluamVjdGlvbiBmbGF3cy4nLFxuICAnNi41LjInOiAnQnVmZmVyIG92ZXJmbG93cycsXG4gICc2LjUuNSc6ICdJbXByb3BlciBlcnJvciBoYW5kbGluZycsXG4gICc2LjUuNyc6ICdDcm9zcy1zaXRlIHNjcmlwdGluZyAoWFNTKScsXG4gICc2LjUuOCc6XG4gICAgJ0ltcHJvcGVyIGFjY2VzcyBjb250cm9sIChzdWNoIGFuIGluc2VjdXJlIGRpcmVjdCBvYmplY3QgcmVmZXJlbmNlcywgZmFpbHVyZSB0byByZXN0cmljdCBVUkwgYWNjZXNzLCBkaXJlY3RvcnkgdHJhdmVyc2FsLCBhbmQgZmFpbHVyZSB0byByZXN0cmljdCB1c2VyIGFjY2VzcyB0byBmdW5jdGlvbnMpLicsXG4gICc2LjUuMTAnOiAnQnJva2VuIGF1dGhlbnRpY2F0aW9uIGFuZCBzZXNzaW9uIG1hbmFnZW1lbnQuJyxcbiAgJzYuNic6IHtcbiAgICBzdGFjazogW1xuICAgICAgJ0ZvciBwdWJsaWMtZmFjaW5nIHdlYiBhcHBsaWNhdGlvbnMsIGFkZHJlc3MgbmV3IHRocmVhdHMgYW5kIHZ1bG5lcmFiaWxpdGllcyBvbiBhbiBvbmdvaW5nIGJhc2lzIGFuZCBlbnN1cmUgdGhlc2UgYXBwbGljYXRpb25zIGFyZSBwcm90ZWN0ZWQgYWdhaW5zdCBrbm93biBhdHRhY2tzIGJ5IGVpdGhlciBvZiB0aGUgZm9sbG93aW5nIG1ldGhvZHM6JyxcbiAgICAgIHsgdGV4dDogJ1xcbicgfSxcbiAgICAgIHtcbiAgICAgICAgdWw6IFtcbiAgICAgICAgICAnUmV2aWV3aW5nIHB1YmxpYy1mYWNpbmcgd2ViIGFwcGxpY2F0aW9ucyB2aWEgbWFudWFsIG9yIGF1dG9tYXRlZCBhcHBsaWNhdGlvbiB2dWxuZXJhYmlsaXR5IHNlY3VyaXR5IGFzc2Vzc21lbnQgdG9vbHMgb3IgbWV0aG9kcywgYXQgbGVhc3QgYW5udWFsbHkgYW5kIGFmdGVyIGFueSBjaGFuZ2VzJyxcbiAgICAgICAgICAnSW5zdGFsbGluZyBhbiBhdXRvbWF0ZWQgdGVjaG5pY2FsIHNvbHV0aW9uIHRoYXQgZGV0ZWN0cyBhbmQgcHJldmVudHMgd2ViLWJhc2VkIGF0dGFja3MgKGZvciBleGFtcGxlLCBhIHdlYi1hcHBsaWNhdGlvbiBmaXJld2FsbCkgaW4gZnJvbnQgb2YgcHVibGljLWZhY2luZyB3ZWIgYXBwbGljYXRpb25zLCB0byBjb250aW51YWxseSBjaGVjayBhbGwgdHJhZmZpYy4nXG4gICAgICAgIF1cbiAgICAgIH1cbiAgICBdXG4gIH0sXG4gICc4LjEuMic6XG4gICAgJ0NvbnRyb2wgYWRkaXRpb24sIGRlbGV0aW9uLCBhbmQgbW9kaWZpY2F0aW9uIG9mIHVzZXIgSURzLCBjcmVkZW50aWFscywgYW5kIG90aGVyIGlkZW50aWZpZXIgb2JqZWN0cy4nLFxuICAnOC4xLjQnOiAnUmVtb3ZlL2Rpc2FibGUgaW5hY3RpdmUgdXNlciBhY2NvdW50cyB3aXRoaW4gOTAgZGF5cy4nLFxuICAnOC4xLjUnOiB7XG4gICAgc3RhY2s6IFtcbiAgICAgICdNYW5hZ2UgSURzIHVzZWQgYnkgdGhpcmQgcGFydGllcyB0byBhY2Nlc3MsIHN1cHBvcnQsIG9yIG1haW50YWluIHN5c3RlbSBjb21wb25lbnRzIHZpYSByZW1vdGUgYWNjZXNzIGFzIGZvbGxvd3M6JyxcbiAgICAgIHsgdGV4dDogJ1xcbicgfSxcbiAgICAgIHtcbiAgICAgICAgdWw6IFtcbiAgICAgICAgICAnRW5hYmxlZCBvbmx5IGR1cmluZyB0aGUgdGltZSBwZXJpb2QgbmVlZGVkIGFuZCBkaXNhYmxlZCB3aGVuIG5vdCBpbiB1c2UuJyxcbiAgICAgICAgICAnTW9uaXRvcmVkIHdoZW4gaW4gdXNlLidcbiAgICAgICAgXVxuICAgICAgfVxuICAgIF1cbiAgfSxcbiAgJzguMS42JzpcbiAgICAnTGltaXQgcmVwZWF0ZWQgYWNjZXNzIGF0dGVtcHRzIGJ5IGxvY2tpbmcgb3V0IHRoZSB1c2VyIElEIGFmdGVyIG5vdCBtb3JlIHRoYW4gc2l4IGF0dGVtcHRzLicsXG4gICc4LjEuOCc6XG4gICAgJ0lmIGEgc2Vzc2lvbiBoYXMgYmVlbiBpZGxlIGZvciBtb3JlIHRoYW4gMTUgbWludXRlcywgcmVxdWlyZSB0aGUgdXNlciB0byByZWF1dGhlbnRpY2F0ZSB0byByZS1hY3RpdmF0ZSB0aGUgdGVybWluYWwgb3Igc2Vzc2lvbi4nLFxuICAnOC4yLjQnOiAnQ2hhbmdlIHVzZXIgcGFzc3dvcmRzL3Bhc3NwaHJhc2VzIGF0IGxlYXN0IG9uY2UgZXZlcnkgOTAgZGF5cy4nLFxuICAnOC41LjEnOlxuICAgICdBZGRpdGlvbmFsIHJlcXVpcmVtZW50IGZvciBzZXJ2aWNlIHByb3ZpZGVyczogU2VydmljZSBwcm92aWRlcnMgd2l0aCByZW1vdGUgYWNjZXNzIHRvIGN1c3RvbWVyIHByZW1pc2VzIChmb3IgZXhhbXBsZSwgZm9yIHN1cHBvcnQgb2YgUE9TIHN5c3RlbXMgb3Igc2VydmVycykgbXVzdCB1c2UgYSB1bmlxdWUgYXV0aGVudGljYXRpb24gY3JlZGVudGlhbCAoc3VjaCBhcyBhIHBhc3N3b3JkL3BocmFzZSkgZm9yIGVhY2ggY3VzdG9tZXIuJyxcbiAgJzguNyc6IHtcbiAgICBzdGFjazogW1xuICAgICAgJ0FsbCBhY2Nlc3MgdG8gYW55IGRhdGFiYXNlIGNvbnRhaW5pbmcgY2FyZGhvbGRlciBkYXRhIChpbmNsdWRpbmcgYWNjZXNzIGJ5IGFwcGxpY2F0aW9ucywgYWRtaW5pc3RyYXRvcnMsIGFuZCBhbGwgb3RoZXIgdXNlcnMpIGlzIHJlc3RyaWN0ZWQgYXMgZm9sbG93czonLFxuICAgICAgeyB0ZXh0OiAnXFxuJyB9LFxuICAgICAge1xuICAgICAgICB1bDogW1xuICAgICAgICAgICdBbGwgdXNlciBhY2Nlc3MgdG8sIHVzZXIgcXVlcmllcyBvZiwgYW5kIHVzZXIgYWN0aW9ucyBvbiBkYXRhYmFzZXMgYXJlIHRocm91Z2ggcHJvZ3JhbW1hdGljIG1ldGhvZHMuJyxcbiAgICAgICAgICAnT25seSBkYXRhYmFzZSBhZG1pbmlzdHJhdG9ycyBoYXZlIHRoZSBhYmlsaXR5IHRvIGRpcmVjdGx5IGFjY2VzcyBvciBxdWVyeSBkYXRhYmFzZXMuJyxcbiAgICAgICAgICAnQXBwbGljYXRpb24gSURzIGZvciBkYXRhYmFzZSBhcHBsaWNhdGlvbnMgY2FuIG9ubHkgYmUgdXNlZCBieSB0aGUgYXBwbGljYXRpb25zIChhbmQgbm90IGJ5IGluZGl2aWR1YWwgdXNlcnMgb3Igb3RoZXIgbm9uLWFwcGxpY2F0aW9uIHByb2Nlc3NlcykuJ1xuICAgICAgICBdXG4gICAgICB9XG4gICAgXVxuICB9LFxuICAnMTAuMSc6XG4gICAgJ0ltcGxlbWVudCBhdWRpdCB0cmFpbHMgdG8gbGluayBhbGwgYWNjZXNzIHRvIHN5c3RlbSBjb21wb25lbnRzIHRvIGVhY2ggaW5kaXZpZHVhbCB1c2VyLicsXG4gICcxMC4yLjEnOiAnQWxsIGluZGl2aWR1YWwgdXNlciBhY2Nlc3NlcyB0byBjYXJkaG9sZGVyIGRhdGEnLFxuICAnMTAuMi4yJzpcbiAgICAnQWxsIGFjdGlvbnMgdGFrZW4gYnkgYW55IGluZGl2aWR1YWwgd2l0aCByb290IG9yIGFkbWluaXN0cmF0aXZlIHByaXZpbGVnZXMuJyxcbiAgJzEwLjIuNCc6ICdJbnZhbGlkIGxvZ2ljYWwgYWNjZXNzIGF0dGVtcHRzJyxcbiAgJzEwLjIuNSc6XG4gICAgJ1VzZSBvZiBhbmQgY2hhbmdlcyB0byBpZGVudGlmaWNhdGlvbiBhbmQgYXV0aGVudGljYXRpb24gbWVjaGFuaXNtcyBpbmNsdWRpbmcgYnV0IG5vdCBsaW1pdGVkIHRvIGNyZWF0aW9uIG9mIG5ldyBhY2NvdW50cyBhbmQgZWxldmF0aW9uIG9mIHByaXZpbGVnZXMgYW5kIGFsbCBjaGFuZ2VzLCBhZGRpdGlvbnMsIG9yIGRlbGV0aW9ucyB0byBhY2NvdW50cyB3aXRoIHJvb3Qgb3IgYWRtaW5pc3RyYXRpdmUgcHJpdmlsZWdlcy4nLFxuICAnMTAuMi42JzogJ0luaXRpYWxpemF0aW9uLCBzdG9wcGluZywgb3IgcGF1c2luZyBvZiB0aGUgYXVkaXQgbG9ncycsXG4gICcxMC4yLjcnOiAnQ3JlYXRpb24gYW5kIGRlbGV0aW9uIG9mIHN5c3RlbSBsZXZlbCBvYmplY3RzJyxcbiAgJzEwLjUuMic6ICdQcm90ZWN0IGF1ZGl0IHRyYWlsIGZpbGVzIGZyb20gdW5hdXRob3JpemVkIG1vZGlmaWNhdGlvbnMnLFxuICAnMTAuNS41JzpcbiAgICAnVXNlIGZpbGUgaW50ZWdyaXR5IG1vbml0b3Jpbmcgb3IgY2hhbmdlIGRldGVjdGlvbiBzb2Z0d2FyZSBvbiBsb2dzIHRvIGVuc3VyZSB0aGF0IGV4aXN0aW5nIGxvZyBkYXRhIGNhbm5vdCBiZSBjaGFuZ2VkIHdpdGhvdXQgZ2VuZXJhdGluZyBhbGVydHMgKGFsdGhvdWdoIG5ldyBkYXRhIGJlaW5nIGFkZGVkIHNob3VsZCBub3QgY2F1c2UgYW4gYWxlcnQpLicsXG4gICcxMC40JzpcbiAgICAnVXNpbmcgdGltZS1zeW5jaHJvbml6YXRpb24gdGVjaG5vbG9neSwgc3luY2hyb25pemUgYWxsIGNyaXRpY2FsIHN5c3RlbSBjbG9ja3MgYW5kIHRpbWVzIGFuZCBlbnN1cmUgdGhhdCB0aGUgZm9sbG93aW5nIGlzIGltcGxlbWVudGVkIGZvciBhY3F1aXJpbmcsIGRpc3RyaWJ1dGluZywgYW5kIHN0b3JpbmcgdGltZS4nLFxuICAnMTAuNic6XG4gICAgJ1JldmlldyBsb2dzIGFuZCBzZWN1cml0eSBldmVudHMgZm9yIGFsbCBzeXN0ZW0gY29tcG9uZW50cyB0byBpZGVudGlmeSBhbm9tYWxpZXMgb3Igc3VzcGljaW91cyBhY3Rpdml0eScsXG4gICcxMC42LjEnOiB7XG4gICAgc3RhY2s6IFtcbiAgICAgICdSZXZpZXcgdGhlIGZvbGxvd2luZyBhdCBsZWFzdCBkYWlseTonLFxuICAgICAgeyB0ZXh0OiAnXFxuJyB9LFxuICAgICAge1xuICAgICAgICB1bDogW1xuICAgICAgICAgICdBbGwgc2VjdXJpdHkgZXZlbnRzLicsXG4gICAgICAgICAgJ0xvZ3Mgb2YgYWxsIHN5c3RlbSBjb21wb25lbnRzIHRoYXQgc3RvcmUsIHByb2Nlc3MsIG9yIHRyYW5zbWl0IENIRCBhbmQvb3IgU0FELCBvciB0aGF0IGNvdWxkIGltcGFjdCB0aGUgc2VjdXJpdHkgb2YgQ0hEIGFuZC9vciBTQUQuJyxcbiAgICAgICAgICAnTG9ncyBvZiBhbGwgY3JpdGljYWwgc3lzdGVtIGNvbXBvbmVudHMuJyxcbiAgICAgICAgICAnTG9ncyBvZiBhbGwgc2VydmVycyBhbmQgc3lzdGVtIGNvbXBvbmVudHMgdGhhdCBwZXJmb3JtIHNlY3VyaXR5IGZ1bmN0aW9ucyAoZm9yIGV4YW1wbGUsIGZpcmV3YWxscywgaW50cnVzaW9uIGRldGVjdGlvbiBzeXN0ZW1zL2ludHJ1c2lvbiBwcmV2ZW50aW9uIHN5c3RlbXMgKElEUy9JUFMpLCBhdXRoZW50aWNhdGlvbiBzZXJ2ZXJzLCBlY29tbWVyY2UgcmVkaXJlY3Rpb24gc2VydmVycywgZXRjLiknXG4gICAgICAgIF1cbiAgICAgIH1cbiAgICBdLFxuICAgIHN0eWxlOiAnc3RhbmRhcmQnXG4gIH0sXG4gICcxMS40JzpcbiAgICAnVXNlIGludHJ1c2lvbiBkZXRlY3Rpb24gYW5kL29yIGludHJ1c2lvbiBwcmV2ZW50aW9uIHRlY2huaXF1ZXMgdG8gZGV0ZWN0IGFuZC9vciBwcmV2ZW50IGludHJ1c2lvbnMgaW50byB0aGUgbmV0d29yay4gTW9uaXRvciBhbGwgdHJhZmZpYyBhdCB0aGUgcGVyaW1ldGVyIG9mIHRoZSBjYXJkaG9sZGVyIGRhdGEgZW52aXJvbm1lbnQgYXMgd2VsbCBhcyBhdCBjcml0aWNhbCBwb2ludHMgaW4gdGhlIGNhcmRob2xkZXIgZGF0YSBlbnZpcm9ubWVudCwgYW5kIGFsZXJ0IHBlcnNvbm5lbCB0byBzdXNwZWN0ZWQgY29tcHJvbWlzZXMuIEtlZXAgYWxsIGludHJ1c2lvbiBkZXRlY3Rpb24gYW5kIHByZXZlbnRpb24gZW5naW5lcywgYmFzZWxpbmVzLCBhbmQgc2lnbmF0dXJlcyB1cCB0byBkYXRlLicsXG4gICcxMS41JzpcbiAgICAnRGVwbG95IGEgY2hhbmdlIGRldGVjdGlvbiBtZWNoYW5pc20gKGZvciBleGFtcGxlLCBmaWxlIGludGVncml0eSBtb25pdG9yaW5nIHRvb2xzKSB0byBhbGVydCBwZXJzb25uZWwgdG8gdW5hdXRob3JpemVkIG1vZGlmaWNhdGlvbiBvZiBjcml0aWNhbCBzeXN0ZW0gZmlsZXMsIGNvbmZpZ3VyYXRpb24gZmlsZXMsIG9yIGNvbnRlbnQgZmlsZXM7IGFuZCBjb25maWd1cmUgdGhlIHNvZnR3YXJlIHRvIHBlcmZvcm0gY3JpdGljYWwgZmlsZSBjb21wYXJpc29ucyBhdCBsZWFzdCB3ZWVrbHkuJ1xufTtcbiJdfQ==
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.UpdateRegistry = void 0;

var _fs = _interopRequireDefault(require("fs"));

var _logger = require("./logger");

var _constants = require("../../common/constants");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

class UpdateRegistry {
  constructor() {
    _defineProperty(this, "busy", void 0);

    _defineProperty(this, "file", void 0);

    this.busy = false;
    this.file = _constants.WAZUH_DATA_CONFIG_REGISTRY_PATH;
  }
  /**
   * Reads the Wazuh registry content
   */


  async readContent() {
    try {
      (0, _logger.log)('update-registry:readContent', 'Reading wazuh-registry.json content', 'debug');
      const content = await _fs.default.readFileSync(this.file, {
        encoding: 'utf-8'
      });
      return JSON.parse(content);
    } catch (error) {
      (0, _logger.log)('update-registry:readContent', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Get the hosts and their cluster info stored in the registry
   */


  async getHosts() {
    try {
      (0, _logger.log)('update-registry:getHosts', 'Getting hosts from registry', 'debug');
      const content = await this.readContent();
      return content.hosts || {};
    } catch (error) {
      (0, _logger.log)('update-registry:getHosts', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Returns the cluster information associated to an API id
   * @param {String} id
   */


  async getHostById(id) {
    try {
      if (!id) throw new Error('API id is missing');
      const hosts = await this.getHosts();
      return hosts.id || {};
    } catch (error) {
      (0, _logger.log)('update-registry:getClusterInfoByAPI', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Writes the wazuh-registry.json
   * @param {Object} content
   */


  async writeContent(content) {
    try {
      (0, _logger.log)('update-registry:writeContent', 'Writting wazuh-registry.json content', 'debug');

      if (this.busy) {
        throw new Error('Another process is updating the registry file');
      }

      this.busy = true;
      await _fs.default.writeFileSync(this.file, JSON.stringify(content));
      this.busy = false;
    } catch (error) {
      (0, _logger.log)('update-registry:writeContent', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Checks if the host exist in order to update the data, otherwise creates it
   * @param {String} id
   * @param {Object} hosts
   */


  checkHost(id, hosts) {
    try {
      return Object.keys(hosts).includes(id);
    } catch (error) {
      (0, _logger.log)('update-registry:checkHost', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Migrates the cluster information and extensions associated to an API id
   * @param {String} id
   * @param {Object} clusterInfo
   * @param {Object} clusterExtensions
   */


  async migrateToRegistry(id, clusterInfo, clusterExtensions) {
    try {
      const content = await this.readContent();
      if (!Object.keys(content).includes('hosts')) Object.assign(content, {
        hosts: {}
      });
      const info = {
        cluster_info: clusterInfo,
        extensions: clusterExtensions
      };
      content.hosts[id] = info;
      await this.writeContent(content);
      (0, _logger.log)('update-registry:migrateToRegistry', `API ${id} was properly migrated`, 'debug');
      return info;
    } catch (error) {
      (0, _logger.log)('update-registry:migrateToRegistry', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Updates the cluster-information or manager-information in the registry
   * @param {String} id
   * @param {Object} clusterInfo
   */


  async updateClusterInfo(id, clusterInfo) {
    try {
      const content = await this.readContent(); // Checks if not exists in order to create

      if (!content.hosts[id]) content.hosts[id] = {};
      content.hosts[id].cluster_info = clusterInfo;
      await this.writeContent(content);
      (0, _logger.log)('update-registry:updateClusterInfo', `API ${id} information was properly updated`, 'debug');
      return id;
    } catch (error) {
      (0, _logger.log)('update-registry:updateClusterInfo', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Updates the cluster-information or manager-information in the registry
   * @param {String} id
   * @param {Object} clusterInfo
   */


  async updateAPIExtensions(id, extensions) {
    try {
      const content = await this.readContent();
      if (content.hosts[id]) content.hosts[id].extensions = extensions;
      await this.writeContent(content);
      (0, _logger.log)('update-registry:updateAPIExtensions', `API ${id} extensions were properly updated`, 'debug');
      return id;
    } catch (error) {
      (0, _logger.log)('update-registry:updateAPIHostname', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Remove the given ids from the registry host entries
   * @param {Array} ids
   */


  async removeHostEntries(ids) {
    try {
      (0, _logger.log)('update-registry:removeHostEntry', 'Removing entry', 'debug');
      const content = await this.readContent();
      ids.forEach(id => delete content.hosts[id]);
      await this.writeContent(content);
    } catch (error) {
      (0, _logger.log)('update-registry:removeHostEntry', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Compare the hosts from wazuh.yml and the host in the wazuh-registry.json file in order to remove the orphan registry register
   * @param {Array} hosts
   */


  async removeOrphanEntries(hosts) {
    try {
      (0, _logger.log)('update-registry:removeOrphanEntries', 'Checking orphan registry entries', 'debug');
      const entries = await this.getHosts();
      const hostsKeys = hosts.map(h => {
        return h.id;
      });
      const entriesKeys = Object.keys(entries);
      const diff = entriesKeys.filter(e => {
        return !hostsKeys.includes(e);
      });
      await this.removeHostEntries(diff);
    } catch (error) {
      (0, _logger.log)('update-registry:removeOrphanEntries', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Returns the token information associated to an API id
   * @param {String} id
   */


  async getTokenById(id) {
    try {
      if (!id) throw new Error('API id is missing');
      const hosts = await this.getHosts();
      return hosts[id] ? hosts[id].token || null : null;
    } catch (error) {
      (0, _logger.log)('update-registry:getTokenById', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Updates the token in the registry
   * @param {String} id
   * @param {String} token
   */


  async updateTokenByHost(id, token) {
    try {
      const content = await this.readContent(); // Checks if not exists in order to create

      if (!content.hosts[id]) content.hosts[id] = {};
      content.hosts[id].token = token;
      await this.writeContent(content);
      (0, _logger.log)('update-registry:updateToken', `API ${id} information was properly updated`, 'debug');
      return id;
    } catch (error) {
      (0, _logger.log)('update-registry:updateToken', error.message || error);
      return Promise.reject(error);
    }
  }

}

exports.UpdateRegistry = UpdateRegistry;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInVwZGF0ZS1yZWdpc3RyeS50cyJdLCJuYW1lcyI6WyJVcGRhdGVSZWdpc3RyeSIsImNvbnN0cnVjdG9yIiwiYnVzeSIsImZpbGUiLCJXQVpVSF9EQVRBX0NPTkZJR19SRUdJU1RSWV9QQVRIIiwicmVhZENvbnRlbnQiLCJjb250ZW50IiwiZnMiLCJyZWFkRmlsZVN5bmMiLCJlbmNvZGluZyIsIkpTT04iLCJwYXJzZSIsImVycm9yIiwibWVzc2FnZSIsIlByb21pc2UiLCJyZWplY3QiLCJnZXRIb3N0cyIsImhvc3RzIiwiZ2V0SG9zdEJ5SWQiLCJpZCIsIkVycm9yIiwid3JpdGVDb250ZW50Iiwid3JpdGVGaWxlU3luYyIsInN0cmluZ2lmeSIsImNoZWNrSG9zdCIsIk9iamVjdCIsImtleXMiLCJpbmNsdWRlcyIsIm1pZ3JhdGVUb1JlZ2lzdHJ5IiwiY2x1c3RlckluZm8iLCJjbHVzdGVyRXh0ZW5zaW9ucyIsImFzc2lnbiIsImluZm8iLCJjbHVzdGVyX2luZm8iLCJleHRlbnNpb25zIiwidXBkYXRlQ2x1c3RlckluZm8iLCJ1cGRhdGVBUElFeHRlbnNpb25zIiwicmVtb3ZlSG9zdEVudHJpZXMiLCJpZHMiLCJmb3JFYWNoIiwicmVtb3ZlT3JwaGFuRW50cmllcyIsImVudHJpZXMiLCJob3N0c0tleXMiLCJtYXAiLCJoIiwiZW50cmllc0tleXMiLCJkaWZmIiwiZmlsdGVyIiwiZSIsImdldFRva2VuQnlJZCIsInRva2VuIiwidXBkYXRlVG9rZW5CeUhvc3QiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFXQTs7QUFDQTs7QUFDQTs7Ozs7O0FBRU8sTUFBTUEsY0FBTixDQUFxQjtBQUcxQkMsRUFBQUEsV0FBVyxHQUFHO0FBQUE7O0FBQUE7O0FBQ1osU0FBS0MsSUFBTCxHQUFZLEtBQVo7QUFDQSxTQUFLQyxJQUFMLEdBQVlDLDBDQUFaO0FBQ0Q7QUFFRDtBQUNGO0FBQ0E7OztBQUNtQixRQUFYQyxXQUFXLEdBQUc7QUFDbEIsUUFBSTtBQUNGLHVCQUFJLDZCQUFK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TnlCIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIE1vZHVsZSB0byB1cGRhdGUgdGhlIGNvbmZpZ3VyYXRpb24gZmlsZVxuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cbmltcG9ydCBmcyBmcm9tICdmcyc7XG5pbXBvcnQgeyBsb2cgfSBmcm9tICcuL2xvZ2dlcic7XG5pbXBvcnQgeyBXQVpVSF9EQVRBX0NPTkZJR19SRUdJU1RSWV9QQVRIIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cyc7XG5cbmV4cG9ydCBjbGFzcyBVcGRhdGVSZWdpc3RyeSB7XG4gIGJ1c3k6IGJvb2xlYW47XG4gIGZpbGU6IHN0cmluZztcbiAgY29uc3RydWN0b3IoKSB7XG4gICAgdGhpcy5idXN5ID0gZmFsc2U7XG4gICAgdGhpcy5maWxlID0gV0FaVUhfREFUQV9DT05GSUdfUkVHSVNUUllfUEFUSDtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZWFkcyB0aGUgV2F6dWggcmVnaXN0cnkgY29udGVudFxuICAgKi9cbiAgYXN5bmMgcmVhZENvbnRlbnQoKSB7XG4gICAgdHJ5IHtcbiAgICAgIGxvZygndXBkYXRlLXJlZ2lzdHJ5OnJlYWRDb250ZW50JywgJ1JlYWRpbmcgd2F6dWgtcmVnaXN0cnkuanNvbiBjb250ZW50JywgJ2RlYnVnJyk7XG4gICAgICBjb25zdCBjb250ZW50ID0gYXdhaXQgZnMucmVhZEZpbGVTeW5jKHRoaXMuZmlsZSwgeyBlbmNvZGluZzogJ3V0Zi04JyB9KTtcbiAgICAgIHJldHVybiBKU09OLnBhcnNlKGNvbnRlbnQpO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3VwZGF0ZS1yZWdpc3RyeTpyZWFkQ29udGVudCcsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogR2V0IHRoZSBob3N0cyBhbmQgdGhlaXIgY2x1c3RlciBpbmZvIHN0b3JlZCBpbiB0aGUgcmVnaXN0cnlcbiAgICovXG4gIGFzeW5jIGdldEhvc3RzKCkge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ3VwZGF0ZS1yZWdpc3RyeTpnZXRIb3N0cycsICdHZXR0aW5nIGhvc3RzIGZyb20gcmVnaXN0cnknLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IGNvbnRlbnQgPSBhd2FpdCB0aGlzLnJlYWRDb250ZW50KCk7XG4gICAgICByZXR1cm4gY29udGVudC5ob3N0cyB8fCB7fTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd1cGRhdGUtcmVnaXN0cnk6Z2V0SG9zdHMnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybnMgdGhlIGNsdXN0ZXIgaW5mb3JtYXRpb24gYXNzb2NpYXRlZCB0byBhbiBBUEkgaWRcbiAgICogQHBhcmFtIHtTdHJpbmd9IGlkXG4gICAqL1xuICBhc3luYyBnZXRIb3N0QnlJZChpZCkge1xuICAgIHRyeSB7XG4gICAgICBpZiAoIWlkKSB0aHJvdyBuZXcgRXJyb3IoJ0FQSSBpZCBpcyBtaXNzaW5nJyk7XG4gICAgICBjb25zdCBob3N0cyA9IGF3YWl0IHRoaXMuZ2V0SG9zdHMoKTtcbiAgICAgIHJldHVybiBob3N0cy5pZCB8fCB7fTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd1cGRhdGUtcmVnaXN0cnk6Z2V0Q2x1c3RlckluZm9CeUFQSScsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogV3JpdGVzIHRoZSB3YXp1aC1yZWdpc3RyeS5qc29uXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZW50XG4gICAqL1xuICBhc3luYyB3cml0ZUNvbnRlbnQoY29udGVudCkge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ3VwZGF0ZS1yZWdpc3RyeTp3cml0ZUNvbnRlbnQnLCAnV3JpdHRpbmcgd2F6dWgtcmVnaXN0cnkuanNvbiBjb250ZW50JywgJ2RlYnVnJyk7XG4gICAgICBpZiAodGhpcy5idXN5KSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignQW5vdGhlciBwcm9jZXNzIGlzIHVwZGF0aW5nIHRoZSByZWdpc3RyeSBmaWxlJyk7XG4gICAgICB9XG4gICAgICB0aGlzLmJ1c3kgPSB0cnVlO1xuICAgICAgYXdhaXQgZnMud3JpdGVGaWxlU3luYyh0aGlzLmZpbGUsIEpTT04uc3RyaW5naWZ5KGNvbnRlbnQpKTtcbiAgICAgIHRoaXMuYnVzeSA9IGZhbHNlO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3VwZGF0ZS1yZWdpc3RyeTp3cml0ZUNvbnRlbnQnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIENoZWNrcyBpZiB0aGUgaG9zdCBleGlzdCBpbiBvcmRlciB0byB1cGRhdGUgdGhlIGRhdGEsIG90aGVyd2lzZSBjcmVhdGVzIGl0XG4gICAqIEBwYXJhbSB7U3RyaW5nfSBpZFxuICAgKiBAcGFyYW0ge09iamVjdH0gaG9zdHNcbiAgICovXG4gIGNoZWNrSG9zdChpZCwgaG9zdHMpIHtcbiAgICB0cnkge1xuICAgICAgcmV0dXJuIE9iamVjdC5rZXlzKGhvc3RzKS5pbmNsdWRlcyhpZCk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygndXBkYXRlLXJlZ2lzdHJ5OmNoZWNrSG9zdCcsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogTWlncmF0ZXMgdGhlIGNsdXN0ZXIgaW5mb3JtYXRpb24gYW5kIGV4dGVuc2lvbnMgYXNzb2NpYXRlZCB0byBhbiBBUEkgaWRcbiAgICogQHBhcmFtIHtTdHJpbmd9IGlkXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjbHVzdGVySW5mb1xuICAgKiBAcGFyYW0ge09iamVjdH0gY2x1c3RlckV4dGVuc2lvbnNcbiAgICovXG4gIGFzeW5jIG1pZ3JhdGVUb1JlZ2lzdHJ5KGlkLCBjbHVzdGVySW5mbywgY2x1c3RlckV4dGVuc2lvbnMpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgY29udGVudCA9IGF3YWl0IHRoaXMucmVhZENvbnRlbnQoKTtcbiAgICAgIGlmICghT2JqZWN0LmtleXMoY29udGVudCkuaW5jbHVkZXMoJ2hvc3RzJykpIE9iamVjdC5hc3NpZ24oY29udGVudCwgeyBob3N0czoge30gfSk7XG4gICAgICBjb25zdCBpbmZvID0geyBjbHVzdGVyX2luZm86IGNsdXN0ZXJJbmZvLCBleHRlbnNpb25zOiBjbHVzdGVyRXh0ZW5zaW9ucyB9O1xuICAgICAgY29udGVudC5ob3N0c1tpZF0gPSBpbmZvO1xuICAgICAgYXdhaXQgdGhpcy53cml0ZUNvbnRlbnQoY29udGVudCk7XG4gICAgICBsb2coJ3VwZGF0ZS1yZWdpc3RyeTptaWdyYXRlVG9SZWdpc3RyeScsIGBBUEkgJHtpZH0gd2FzIHByb3Blcmx5IG1pZ3JhdGVkYCwgJ2RlYnVnJyk7XG4gICAgICByZXR1cm4gaW5mbztcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd1cGRhdGUtcmVnaXN0cnk6bWlncmF0ZVRvUmVnaXN0cnknLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFVwZGF0ZXMgdGhlIGNsdXN0ZXItaW5mb3JtYXRpb24gb3IgbWFuYWdlci1pbmZvcm1hdGlvbiBpbiB0aGUgcmVnaXN0cnlcbiAgICogQHBhcmFtIHtTdHJpbmd9IGlkXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjbHVzdGVySW5mb1xuICAgKi9cbiAgYXN5bmMgdXBkYXRlQ2x1c3RlckluZm8oaWQsIGNsdXN0ZXJJbmZvKSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IGNvbnRlbnQgPSBhd2FpdCB0aGlzLnJlYWRDb250ZW50KCk7XG4gICAgICAvLyBDaGVja3MgaWYgbm90IGV4aXN0cyBpbiBvcmRlciB0byBjcmVhdGVcbiAgICAgIGlmICghY29udGVudC5ob3N0c1tpZF0pIGNvbnRlbnQuaG9zdHNbaWRdID0ge307XG4gICAgICBjb250ZW50Lmhvc3RzW2lkXS5jbHVzdGVyX2luZm8gPSBjbHVzdGVySW5mbztcbiAgICAgIGF3YWl0IHRoaXMud3JpdGVDb250ZW50KGNvbnRlbnQpO1xuICAgICAgbG9nKFxuICAgICAgICAndXBkYXRlLXJlZ2lzdHJ5OnVwZGF0ZUNsdXN0ZXJJbmZvJyxcbiAgICAgICAgYEFQSSAke2lkfSBpbmZvcm1hdGlvbiB3YXMgcHJvcGVybHkgdXBkYXRlZGAsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICByZXR1cm4gaWQ7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygndXBkYXRlLXJlZ2lzdHJ5OnVwZGF0ZUNsdXN0ZXJJbmZvJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBVcGRhdGVzIHRoZSBjbHVzdGVyLWluZm9ybWF0aW9uIG9yIG1hbmFnZXItaW5mb3JtYXRpb24gaW4gdGhlIHJlZ2lzdHJ5XG4gICAqIEBwYXJhbSB7U3RyaW5nfSBpZFxuICAgKiBAcGFyYW0ge09iamVjdH0gY2x1c3RlckluZm9cbiAgICovXG4gIGFzeW5jIHVwZGF0ZUFQSUV4dGVuc2lvbnMoaWQsIGV4dGVuc2lvbnMpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgY29udGVudCA9IGF3YWl0IHRoaXMucmVhZENvbnRlbnQoKTtcbiAgICAgIGlmKGNvbnRlbnQuaG9zdHNbaWRdKSBjb250ZW50Lmhvc3RzW2lkXS5leHRlbnNpb25zID0gZXh0ZW5zaW9ucztcbiAgICAgIGF3YWl0IHRoaXMud3JpdGVDb250ZW50KGNvbnRlbnQpO1xuICAgICAgbG9nKFxuICAgICAgICAndXBkYXRlLXJlZ2lzdHJ5OnVwZGF0ZUFQSUV4dGVuc2lvbnMnLFxuICAgICAgICBgQVBJICR7aWR9IGV4dGVuc2lvbnMgd2VyZSBwcm9wZXJseSB1cGRhdGVkYCxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcbiAgICAgIHJldHVybiBpZDtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd1cGRhdGUtcmVnaXN0cnk6dXBkYXRlQVBJSG9zdG5hbWUnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFJlbW92ZSB0aGUgZ2l2ZW4gaWRzIGZyb20gdGhlIHJlZ2lzdHJ5IGhvc3QgZW50cmllc1xuICAgKiBAcGFyYW0ge0FycmF5fSBpZHNcbiAgICovXG4gIGFzeW5jIHJlbW92ZUhvc3RFbnRyaWVzKGlkcykge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ3VwZGF0ZS1yZWdpc3RyeTpyZW1vdmVIb3N0RW50cnknLCAnUmVtb3ZpbmcgZW50cnknLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IGNvbnRlbnQgPSBhd2FpdCB0aGlzLnJlYWRDb250ZW50KCk7XG4gICAgICBpZHMuZm9yRWFjaChpZCA9PiBkZWxldGUgY29udGVudC5ob3N0c1tpZF0pO1xuICAgICAgYXdhaXQgdGhpcy53cml0ZUNvbnRlbnQoY29udGVudCk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygndXBkYXRlLXJlZ2lzdHJ5OnJlbW92ZUhvc3RFbnRyeScsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogQ29tcGFyZSB0aGUgaG9zdHMgZnJvbSB3YXp1aC55bWwgYW5kIHRoZSBob3N0IGluIHRoZSB3YXp1aC1yZWdpc3RyeS5qc29uIGZpbGUgaW4gb3JkZXIgdG8gcmVtb3ZlIHRoZSBvcnBoYW4gcmVnaXN0cnkgcmVnaXN0ZXJcbiAgICogQHBhcmFtIHtBcnJheX0gaG9zdHNcbiAgICovXG4gIGFzeW5jIHJlbW92ZU9ycGhhbkVudHJpZXMoaG9zdHMpIHtcbiAgICB0cnkge1xuICAgICAgbG9nKCd1cGRhdGUtcmVnaXN0cnk6cmVtb3ZlT3JwaGFuRW50cmllcycsICdDaGVja2luZyBvcnBoYW4gcmVnaXN0cnkgZW50cmllcycsICdkZWJ1ZycpO1xuICAgICAgY29uc3QgZW50cmllcyA9IGF3YWl0IHRoaXMuZ2V0SG9zdHMoKTtcbiAgICAgIGNvbnN0IGhvc3RzS2V5cyA9IGhvc3RzLm1hcChoID0+IHtcbiAgICAgICAgcmV0dXJuIGguaWQ7XG4gICAgICB9KTtcbiAgICAgIGNvbnN0IGVudHJpZXNLZXlzID0gT2JqZWN0LmtleXMoZW50cmllcyk7XG4gICAgICBjb25zdCBkaWZmID0gZW50cmllc0tleXMuZmlsdGVyKGUgPT4ge1xuICAgICAgICByZXR1cm4gIWhvc3RzS2V5cy5pbmNsdWRlcyhlKTtcbiAgICAgIH0pO1xuICAgICAgYXdhaXQgdGhpcy5yZW1vdmVIb3N0RW50cmllcyhkaWZmKTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd1cGRhdGUtcmVnaXN0cnk6cmVtb3ZlT3JwaGFuRW50cmllcycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJucyB0aGUgdG9rZW4gaW5mb3JtYXRpb24gYXNzb2NpYXRlZCB0byBhbiBBUEkgaWRcbiAgICogQHBhcmFtIHtTdHJpbmd9IGlkXG4gICAqL1xuICBhc3luYyBnZXRUb2tlbkJ5SWQoaWQpIHtcbiAgICB0cnkge1xuICAgICAgaWYgKCFpZCkgdGhyb3cgbmV3IEVycm9yKCdBUEkgaWQgaXMgbWlzc2luZycpO1xuICAgICAgY29uc3QgaG9zdHMgPSBhd2FpdCB0aGlzLmdldEhvc3RzKCk7XG4gICAgICByZXR1cm4gaG9zdHNbaWRdID8gaG9zdHNbaWRdLnRva2VuIHx8IG51bGwgOiBudWxsO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3VwZGF0ZS1yZWdpc3RyeTpnZXRUb2tlbkJ5SWQnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFVwZGF0ZXMgdGhlIHRva2VuIGluIHRoZSByZWdpc3RyeVxuICAgKiBAcGFyYW0ge1N0cmluZ30gaWRcbiAgICogQHBhcmFtIHtTdHJpbmd9IHRva2VuXG4gICAqL1xuICBhc3luYyB1cGRhdGVUb2tlbkJ5SG9zdChpZCwgdG9rZW4pIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgY29udGVudCA9IGF3YWl0IHRoaXMucmVhZENvbnRlbnQoKTtcbiAgICAgIC8vIENoZWNrcyBpZiBub3QgZXhpc3RzIGluIG9yZGVyIHRvIGNyZWF0ZVxuICAgICAgaWYgKCFjb250ZW50Lmhvc3RzW2lkXSkgY29udGVudC5ob3N0c1tpZF0gPSB7fTtcbiAgICAgIGNvbnRlbnQuaG9zdHNbaWRdLnRva2VuID0gdG9rZW47XG4gICAgICBhd2FpdCB0aGlzLndyaXRlQ29udGVudChjb250ZW50KTtcbiAgICAgIGxvZygndXBkYXRlLXJlZ2lzdHJ5OnVwZGF0ZVRva2VuJywgYEFQSSAke2lkfSBpbmZvcm1hdGlvbiB3YXMgcHJvcGVybHkgdXBkYXRlZGAsICdkZWJ1ZycpO1xuICAgICAgcmV0dXJuIGlkO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3VwZGF0ZS1yZWdpc3RyeTp1cGRhdGVUb2tlbicsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cbn1cbiJdfQ==
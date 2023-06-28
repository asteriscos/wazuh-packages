"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.BaseLogger = void 0;

var _winston = _interopRequireDefault(require("winston"));

var _fs = _interopRequireDefault(require("fs"));

var _path = _interopRequireDefault(require("path"));

var _getConfiguration = require("./get-configuration");

var _filesystem = require("./filesystem");

var _constants = require("../../common/constants");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

class BaseLogger {
  constructor(plainLogsFile, rawLogsFile) {
    _defineProperty(this, "allowed", false);

    _defineProperty(this, "wazuhLogger", undefined);

    _defineProperty(this, "wazuhPlainLogger", undefined);

    _defineProperty(this, "PLAIN_LOGS_PATH", '');

    _defineProperty(this, "PLAIN_LOGS_FILE_NAME", '');

    _defineProperty(this, "RAW_LOGS_PATH", '');

    _defineProperty(this, "RAW_LOGS_FILE_NAME", '');

    _defineProperty(this, "initLogger", () => {
      const configurationFile = (0, _getConfiguration.getConfiguration)();
      const level = typeof (configurationFile || {})['logs.level'] !== 'undefined' && ['info', 'debug'].includes(configurationFile['logs.level']) ? configurationFile['logs.level'] : 'info'; // JSON logger

      this.wazuhLogger = _winston.default.createLogger({
        level,
        format: _winston.default.format.json(),
        transports: [new _winston.default.transports.File({
          filename: this.RAW_LOGS_PATH
        })]
      }); // Prevents from exit on error related to the logger.

      this.wazuhLogger.exitOnError = false; // Plain text logger

      this.wazuhPlainLogger = _winston.default.createLogger({
        level,
        format: _winston.default.format.simple(),
        transports: [new _winston.default.transports.File({
          filename: this.PLAIN_LOGS_PATH
        })]
      }); // Prevents from exit on error related to the logger.

      this.wazuhPlainLogger.exitOnError = false;
    });

    _defineProperty(this, "initDirectory", async () => {
      try {
        (0, _filesystem.createDataDirectoryIfNotExists)();
        (0, _filesystem.createDataDirectoryIfNotExists)('logs');

        if (typeof this.wazuhLogger === 'undefined' || typeof this.wazuhPlainLogger === 'undefined') {
          this.initLogger();
        }

        this.allowed = true;
        return;
      } catch (error) {
        this.allowed = false;
        return Promise.reject(error);
      }
    });

    _defineProperty(this, "getFilesizeInMegaBytes", filename => {
      if (this.allowed) {
        if (_fs.default.existsSync(filename)) {
          const stats = _fs.default.statSync(filename);

          const fileSizeInMegaBytes = stats.size;
          return fileSizeInMegaBytes / 1000000.0;
        }
      }

      return 0;
    });

    _defineProperty(this, "checkFileExist", filename => {
      return _fs.default.existsSync(filename);
    });

    _defineProperty(this, "rotateFiles", (file, pathFile, log) => {
      if (this.getFilesizeInMegaBytes(pathFile) >= _constants.MAX_MB_LOG_FILES) {
        const fileExtension = _path.default.extname(file);

        const fileName = _path.default.basename(file, fileExtension);

        _fs.default.renameSync(pathFile, `${_constants.WAZUH_DATA_LOGS_DIRECTORY_PATH}/${fileName}-${new Date().getTime()}${fileExtension}`);

        if (log) {
          _fs.default.writeFileSync(pathFile, log + '\n');
        }
      }
    });

    _defineProperty(this, "checkFiles", () => {
      (0, _filesystem.createLogFileIfNotExists)(this.RAW_LOGS_PATH);
      (0, _filesystem.createLogFileIfNotExists)(this.PLAIN_LOGS_PATH);

      if (this.allowed) {
        // check raw log file
        this.rotateFiles(this.RAW_LOGS_FILE_NAME, this.RAW_LOGS_PATH, JSON.stringify({
          date: new Date(),
          level: 'info',
          location: 'logger',
          message: 'Rotated log file'
        })); // check log file

        this.rotateFiles(this.PLAIN_LOGS_FILE_NAME, this.PLAIN_LOGS_PATH);
      }
    });

    _defineProperty(this, "yyyymmdd", () => {
      const now = new Date();
      const y = now.getFullYear();
      const m = now.getMonth() + 1;
      const d = now.getDate();
      const seconds = now.getSeconds();
      const minutes = now.getMinutes();
      const hour = now.getHours();
      return `${y}/${m < 10 ? '0' : ''}${m}/${d < 10 ? '0' : ''}${d} ${hour}:${minutes}:${seconds}`;
    });

    _defineProperty(this, "parseData", data => {
      let parsedData = data instanceof Error ? {
        message: data.message,
        stack: data.stack
      } : data; // when error is AxiosError, it extends from Error

      if (data.isAxiosError) {
        const {
          config
        } = data;
        parsedData = { ...parsedData,
          config: {
            url: config.url,
            method: config.method,
            data: config.data,
            params: config.params
          }
        };
      }

      if (typeof parsedData === 'object') parsedData.toString = () => JSON.stringify(parsedData);
      return parsedData;
    });

    this.PLAIN_LOGS_PATH = _path.default.join(_constants.WAZUH_DATA_LOGS_DIRECTORY_PATH, plainLogsFile);
    this.RAW_LOGS_PATH = _path.default.join(_constants.WAZUH_DATA_LOGS_DIRECTORY_PATH, rawLogsFile);
    this.PLAIN_LOGS_FILE_NAME = plainLogsFile;
    this.RAW_LOGS_FILE_NAME = rawLogsFile;
  }
  /**
   * Initialize loggers, plain and raw logger
   */


  /**
   * Main function to add a new log
   * @param {*} location File where the log is being thrown
   * @param {*} data Message or object to log
   * @param {*} level Optional, default is 'error'
   */
  async log(location, data, level) {
    const parsedData = this.parseData(data);
    return this.initDirectory().then(() => {
      if (this.allowed) {
        this.checkFiles();
        const plainLogData = {
          level: level || 'error',
          message: `${this.yyyymmdd()}: ${location || 'Unknown origin'}: ${parsedData.toString() || 'An error occurred'}`
        };
        this.wazuhPlainLogger.log(plainLogData);
        const logData = {
          date: new Date(),
          level: level || 'error',
          location: location || 'Unknown origin',
          data: parsedData || 'An error occurred'
        };

        if (typeof data == 'string') {
          logData.message = parsedData;
          delete logData.data;
        }

        this.wazuhLogger.log(logData);
      }
    }).catch(error => {
      console.error(`Cannot create the logs directory due to:\n${error.message || error}`);
      throw error;
    });
  }

}

exports.BaseLogger = BaseLogger;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImJhc2UtbG9nZ2VyLnRzIl0sIm5hbWVzIjpbIkJhc2VMb2dnZXIiLCJjb25zdHJ1Y3RvciIsInBsYWluTG9nc0ZpbGUiLCJyYXdMb2dzRmlsZSIsInVuZGVmaW5lZCIsImNvbmZpZ3VyYXRpb25GaWxlIiwibGV2ZWwiLCJpbmNsdWRlcyIsIndhenVoTG9nZ2VyIiwid2luc3RvbiIsImNyZWF0ZUxvZ2dlciIsImZvcm1hdCIsImpzb24iLCJ0cmFuc3BvcnRzIiwiRmlsZSIsImZpbGVuYW1lIiwiUkFXX0xPR1NfUEFUSCIsImV4aXRPbkVycm9yIiwid2F6dWhQbGFpbkxvZ2dlciIsInNpbXBsZSIsIlBMQUlOX0xPR1NfUEFUSCIsImluaXRMb2dnZXIiLCJhbGxvd2VkIiwiZXJyb3IiLCJQcm9taXNlIiwicmVqZWN0IiwiZnMiLCJleGlzdHNTeW5jIiwic3RhdHMiLCJzdGF0U3luYyIsImZpbGVTaXplSW5NZWdhQnl0ZXMiLCJzaXplIiwiZmlsZSIsInBhdGhGaWxlIiwibG9nIiwiZ2V0RmlsZXNpemVJbk1lZ2FCeXRlcyIsIk1BWF9NQl9MT0dfRklMRVMiLCJmaWxlRXh0ZW5zaW9uIiwicGF0aCIsImV4dG5hbWUiLCJmaWxlTmFtZSIsImJhc2VuYW1lIiwicmVuYW1lU3luYyIsIldBWlVIX0RBVEFfTE9HU19ESVJFQ1RPUllfUEFUSCIsIkRhdGUiLCJnZXRUaW1lIiwid3JpdGVGaWxlU3luYyIsInJvdGF0ZUZpbGVzIiwiUkFXX0xPR1NfRklMRV9OQU1FIiwiSlNPTiIsInN0cmluZ2lmeSIsImRhdGUiLCJsb2NhdGlvbiIsIm1lc3NhZ2UiLCJQTEFJTl9MT0dTX0ZJTEVfTkFNRSIsIm5vdyIsInkiLCJnZXRGdWxsWWVhciIsIm0iLCJnZXRNb250aCIsImQiLCJnZXREYXRlIiwic2Vjb25kcyIsImdldFNlY29uZHMiLCJtaW51dGVzIiwiZ2V0TWludXRlcyIsImhvdXIiLCJnZXRIb3VycyIsImRhdGEiLCJwYXJzZWREYXRhIiwiRXJyb3IiLCJzdGFjayIsImlzQXhpb3NFcnJvciIsImNvbmZpZyIsInVybCIsIm1ldGhvZCIsInBhcmFtcyIsInRvU3RyaW5nIiwiam9pbiIsInBhcnNlRGF0YSIsImluaXREaXJlY3RvcnkiLCJ0aGVuIiwiY2hlY2tGaWxlcyIsInBsYWluTG9nRGF0YSIsInl5eXltbWRkIiwibG9nRGF0YSIsImNhdGNoIiwiY29uc29sZSJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQVlBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUVBOzs7Ozs7QUFhTyxNQUFNQSxVQUFOLENBQWlCO0FBU3RCQyxFQUFBQSxXQUFXLENBQUNDLGFBQUQsRUFBd0JDLFdBQXhCLEVBQTZDO0FBQUEscUNBUnJDLEtBUXFDOztBQUFBLHlDQVBkQyxTQU9jOztBQUFBLDhDQU5UQSxTQU1TOztBQUFBLDZDQUw5QixFQUs4Qjs7QUFBQSxrREFKekIsRUFJeUI7O0FBQUEsMkNBSGhDLEVBR2dDOztBQUFBLGdEQUYzQixFQUUyQjs7QUFBQSx3Q0FVbkMsTUFBTTtBQUN6QixZQUFNQyxpQkFBaUIsR0FBRyx5Q0FBMUI7QUFDQSxZQUFNQyxLQUFLLEdBQ1QsT0FBTyxDQUFDRCxpQkFBaUIsSUFBSSxFQUF0QixFQUEwQixZQUExQixDQUFQLEtBQW1ELFdBQW5ELElBQ0EsQ0FBQyxNQUFELEVBQVMsT0FBVCxFQUFrQkUsUUFBbEIsQ0FBMkJGLGlCQUFpQixDQUFDLFlBQUQsQ0FBNUMsQ0FEQSxHQUVJQSxpQkFBaUIsQ0FBQyxZQUFELENBRnJCLEdBR0ksTUFKTixDQUZ5QixDQVF6Qjs7QUFDQSxXQUFLRyxXQUFMLEdBQW1CQyxpQkFBUUMsWUFBUixDQUFxQjtBQUN0Q0osUUFBQUEsS0FEc0M7QUFFdENLLFFBQUFBLE1BQU0sRUFBRUYsaUJBQVFFLE1BQVIsQ0FBZUMsSUFBZixFQUY4QjtBQUd0Q0MsUUFBQUEsVUFBVSxFQUFFLENBQ1YsSUFBSUosaUJBQVFJLFVBQVIsQ0FBbUJDLElBQXZCLENBQTRCO0FBQzFCQyxVQUFBQSxRQUFRLEVBQUUsS0FBS0M7QUFEVyxTQUE1QixDQURV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QUNRLFFBQVgsTUFBeUIsbUJBQzFCO0FBSjBDLFNBQTdDO0FBT0EsYUFBSzNELGdCQUFMLENBQXNCZ0IsR0FBdEIsQ0FBMEJpRCxZQUExQjtBQUVBLGNBQU1FLE9BQTBCLEdBQUc7QUFDakNsQyxVQUFBQSxJQUFJLEVBQUUsSUFBSVAsSUFBSixFQUQyQjtBQUVqQ3RDLFVBQUFBLEtBQUssRUFBRUEsS0FBSyxJQUFJLE9BRmlCO0FBR2pDOEMsVUFBQUEsUUFBUSxFQUFFQSxRQUFRLElBQUksZ0JBSFc7QUFJakNnQixVQUFBQSxJQUFJLEVBQUVDLFVBQVUsSUFBSTtBQUphLFNBQW5DOztBQU9BLFlBQUksT0FBT0QsSUFBUCxJQUFlLFFBQW5CLEVBQTZCO0FBQzNCaUIsVUFBQUEsT0FBTyxDQUFDaEMsT0FBUixHQUFrQmdCLFVBQWxCO0FBQ0EsaUJBQU9nQixPQUFPLENBQUNqQixJQUFmO0FBQ0Q7O0FBRUQsYUFBSzVELFdBQUwsQ0FBaUIwQixHQUFqQixDQUFxQm1ELE9BQXJCO0FBQ0Q7QUFDRixLQTNCSSxFQTRCSkMsS0E1QkksQ0E0QkcvRCxLQUFELElBQVc7QUFDaEJnRSxNQUFBQSxPQUFPLENBQUNoRSxLQUFSLENBQWUsNkNBQTRDQSxLQUFLLENBQUM4QixPQUFOLElBQWlCOUIsS0FBTSxFQUFsRjtBQUNBLFlBQU1BLEtBQU47QUFDRCxLQS9CSSxDQUFQO0FBZ0NEOztBQWhPcUIiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gU2V0dGluZ3MgY29udHJvbGxlclxuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cblxuaW1wb3J0IHdpbnN0b24gZnJvbSAnd2luc3Rvbic7XG5pbXBvcnQgZnMgZnJvbSAnZnMnO1xuaW1wb3J0IHBhdGggZnJvbSAncGF0aCc7XG5pbXBvcnQgeyBnZXRDb25maWd1cmF0aW9uIH0gZnJvbSAnLi9nZXQtY29uZmlndXJhdGlvbic7XG5pbXBvcnQgeyBjcmVhdGVEYXRhRGlyZWN0b3J5SWZOb3RFeGlzdHMsIGNyZWF0ZUxvZ0ZpbGVJZk5vdEV4aXN0cyB9IGZyb20gJy4vZmlsZXN5c3RlbSc7XG5cbmltcG9ydCB7IFdBWlVIX0RBVEFfTE9HU19ESVJFQ1RPUllfUEFUSCwgTUFYX01CX0xPR19GSUxFUyB9IGZyb20gJy4uLy4uL2NvbW1vbi9jb25zdGFudHMnO1xuXG5leHBvcnQgaW50ZXJmYWNlIElVSVBsYWluTG9nZ2VyU2V0dGluZ3Mge1xuICBsZXZlbDogc3RyaW5nO1xuICBtZXNzYWdlPzogc3RyaW5nO1xuICBkYXRhPzogYW55O1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIElVSUxvZ2dlclNldHRpbmdzIGV4dGVuZHMgSVVJUGxhaW5Mb2dnZXJTZXR0aW5ncyB7XG4gIGRhdGU6IERhdGU7XG4gIGxvY2F0aW9uOiBzdHJpbmc7XG59XG5cbmV4cG9ydCBjbGFzcyBCYXNlTG9nZ2VyIHtcbiAgYWxsb3dlZDogYm9vbGVhbiA9IGZhbHNlO1xuICB3YXp1aExvZ2dlcjogd2luc3Rvbi5Mb2dnZXIgfCB1bmRlZmluZWQgPSB1bmRlZmluZWQ7XG4gIHdhenVoUGxhaW5Mb2dnZXI6IHdpbnN0b24uTG9nZ2VyIHwgdW5kZWZpbmVkID0gdW5kZWZpbmVkO1xuICBQTEFJTl9MT0dTX1BBVEg6IHN0cmluZyA9ICcnO1xuICBQTEFJTl9MT0dTX0ZJTEVfTkFNRTogc3RyaW5nID0gJyc7XG4gIFJBV19MT0dTX1BBVEg6IHN0cmluZyA9ICcnO1xuICBSQVdfTE9HU19GSUxFX05BTUU6IHN0cmluZyA9ICcnO1xuXG4gIGNvbnN0cnVjdG9yKHBsYWluTG9nc0ZpbGU6IHN0cmluZywgcmF3TG9nc0ZpbGU6IHN0cmluZykge1xuICAgIHRoaXMuUExBSU5fTE9HU19QQVRIID0gcGF0aC5qb2luKFdBWlVIX0RBVEFfTE9HU19ESVJFQ1RPUllfUEFUSCwgcGxhaW5Mb2dzRmlsZSk7XG4gICAgdGhpcy5SQVdfTE9HU19QQVRIID0gcGF0aC5qb2luKFdBWlVIX0RBVEFfTE9HU19ESVJFQ1RPUllfUEFUSCwgcmF3TG9nc0ZpbGUpO1xuICAgIHRoaXMuUExBSU5fTE9HU19GSUxFX05BTUUgPSBwbGFpbkxvZ3NGaWxlO1xuICAgIHRoaXMuUkFXX0xPR1NfRklMRV9OQU1FID0gcmF3TG9nc0ZpbGU7XG4gIH1cblxuICAvKipcbiAgICogSW5pdGlhbGl6ZSBsb2dnZXJzLCBwbGFpbiBhbmQgcmF3IGxvZ2dlclxuICAgKi9cbiAgcHJpdmF0ZSBpbml0TG9nZ2VyID0gKCkgPT4ge1xuICAgIGNvbnN0IGNvbmZpZ3VyYXRpb25GaWxlID0gZ2V0Q29uZmlndXJhdGlvbigpO1xuICAgIGNvbnN0IGxldmVsID1cbiAgICAgIHR5cGVvZiAoY29uZmlndXJhdGlvbkZpbGUgfHwge30pWydsb2dzLmxldmVsJ10gIT09ICd1bmRlZmluZWQnICYmXG4gICAgICBbJ2luZm8nLCAnZGVidWcnXS5pbmNsdWRlcyhjb25maWd1cmF0aW9uRmlsZVsnbG9ncy5sZXZlbCddKVxuICAgICAgICA/IGNvbmZpZ3VyYXRpb25GaWxlWydsb2dzLmxldmVsJ11cbiAgICAgICAgOiAnaW5mbyc7XG5cbiAgICAvLyBKU09OIGxvZ2dlclxuICAgIHRoaXMud2F6dWhMb2dnZXIgPSB3aW5zdG9uLmNyZWF0ZUxvZ2dlcih7XG4gICAgICBsZXZlbCxcbiAgICAgIGZvcm1hdDogd2luc3Rvbi5mb3JtYXQuanNvbigpLFxuICAgICAgdHJhbnNwb3J0czogW1xuICAgICAgICBuZXcgd2luc3Rvbi50cmFuc3BvcnRzLkZpbGUoe1xuICAgICAgICAgIGZpbGVuYW1lOiB0aGlzLlJBV19MT0dTX1BBVEgsXG4gICAgICAgIH0pLFxuICAgICAgXSxcbiAgICB9KTtcblxuICAgIC8vIFByZXZlbnRzIGZyb20gZXhpdCBvbiBlcnJvciByZWxhdGVkIHRvIHRoZSBsb2dnZXIuXG4gICAgdGhpcy53YXp1aExvZ2dlci5leGl0T25FcnJvciA9IGZhbHNlO1xuXG4gICAgLy8gUGxhaW4gdGV4dCBsb2dnZXJcbiAgICB0aGlzLndhenVoUGxhaW5Mb2dnZXIgPSB3aW5zdG9uLmNyZWF0ZUxvZ2dlcih7XG4gICAgICBsZXZlbCxcbiAgICAgIGZvcm1hdDogd2luc3Rvbi5mb3JtYXQuc2ltcGxlKCksXG4gICAgICB0cmFuc3BvcnRzOiBbXG4gICAgICAgIG5ldyB3aW5zdG9uLnRyYW5zcG9ydHMuRmlsZSh7XG4gICAgICAgICAgZmlsZW5hbWU6IHRoaXMuUExBSU5fTE9HU19QQVRILFxuICAgICAgICB9KSxcbiAgICAgIF0sXG4gICAgfSk7XG5cbiAgICAvLyBQcmV2ZW50cyBmcm9tIGV4aXQgb24gZXJyb3IgcmVsYXRlZCB0byB0aGUgbG9nZ2VyLlxuICAgIHRoaXMud2F6dWhQbGFpbkxvZ2dlci5leGl0T25FcnJvciA9IGZhbHNlO1xuICB9O1xuXG4gIC8qKlxuICAgKiBDaGVja3MgaWYgd2F6dWgvbG9ncyBleGlzdHMuIElmIGl0IGRvZXNuJ3QgZXhpc3QsIGl0IHdpbGwgYmUgY3JlYXRlZC5cbiAgICovXG4gIGluaXREaXJlY3RvcnkgPSBhc3luYyAoKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNyZWF0ZURhdGFEaXJlY3RvcnlJZk5vdEV4aXN0cygpO1xuICAgICAgY3JlYXRlRGF0YURpcmVjdG9yeUlmTm90RXhpc3RzKCdsb2dzJyk7XG4gICAgICBpZiAodHlwZW9mIHRoaXMud2F6dWhMb2dnZXIgPT09ICd1bmRlZmluZWQnIHx8IHR5cGVvZiB0aGlzLndhenVoUGxhaW5Mb2dnZXIgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICAgIHRoaXMuaW5pdExvZ2dlcigpO1xuICAgICAgfVxuICAgICAgdGhpcy5hbGxvd2VkID0gdHJ1ZTtcbiAgICAgIHJldHVybjtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgdGhpcy5hbGxvd2VkID0gZmFsc2U7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfTtcblxuICAvKipcbiAgICogUmV0dXJucyBnaXZlbiBmaWxlIHNpemUgaW4gTUIsIGlmIHRoZSBmaWxlIGRvZXNuJ3QgZXhpc3QgcmV0dXJucyAwXG4gICAqIEBwYXJhbSB7Kn0gZmlsZW5hbWUgUGF0aCB0byB0aGUgZmlsZVxuICAgKi9cbiAgZ2V0RmlsZXNpemVJbk1lZ2FCeXRlcyA9IChmaWxlbmFtZSkgPT4ge1xuICAgIGlmICh0aGlzLmFsbG93ZWQpIHtcbiAgICAgIGlmIChmcy5leGlzdHNTeW5jKGZpbGVuYW1lKSkge1xuICAgICAgICBjb25zdCBzdGF0cyA9IGZzLnN0YXRTeW5jKGZpbGVuYW1lKTtcbiAgICAgICAgY29uc3QgZmlsZVNpemVJbk1lZ2FCeXRlcyA9IHN0YXRzLnNpemU7XG5cbiAgICAgICAgcmV0dXJuIGZpbGVTaXplSW5NZWdhQnl0ZXMgLyAxMDAwMDAwLjA7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiAwO1xuICB9O1xuXG4gIC8qKlxuICAgKiBDaGVjayBpZiBmaWxlIGV4aXN0XG4gICAqIEBwYXJhbSBmaWxlbmFtZVxuICAgKiBAcmV0dXJucyBib29sZWFuXG4gICAqL1xuICBjaGVja0ZpbGVFeGlzdCA9IChmaWxlbmFtZSkgPT4ge1xuICAgIHJldHVybiBmcy5leGlzdHNTeW5jKGZpbGVuYW1lKTtcbiAgfTtcblxuICByb3RhdGVGaWxlcyA9IChmaWxlOiBzdHJpbmcsIHBhdGhGaWxlOiBzdHJpbmcsIGxvZz86IHN0cmluZykgPT4ge1xuICAgIGlmICh0aGlzLmdldEZpbGVzaXplSW5NZWdhQnl0ZXMocGF0aEZpbGUpID49IE1BWF9NQl9MT0dfRklMRVMpIHtcbiAgICAgIGNvbnN0IGZpbGVFeHRlbnNpb24gPSBwYXRoLmV4dG5hbWUoZmlsZSk7XG4gICAgICBjb25zdCBmaWxlTmFtZSA9IHBhdGguYmFzZW5hbWUoZmlsZSwgZmlsZUV4dGVuc2lvbik7XG4gICAgICBmcy5yZW5hbWVTeW5jKFxuICAgICAgICBwYXRoRmlsZSxcbiAgICAgICAgYCR7V0FaVUhfREFUQV9MT0dTX0RJUkVDVE9SWV9QQVRIfS8ke2ZpbGVOYW1lfS0ke25ldyBEYXRlKCkuZ2V0VGltZSgpfSR7ZmlsZUV4dGVuc2lvbn1gXG4gICAgICApO1xuICAgICAgaWYgKGxvZykge1xuICAgICAgICBmcy53cml0ZUZpbGVTeW5jKHBhdGhGaWxlLCBsb2cgKyAnXFxuJyk7XG4gICAgICB9XG4gICAgfVxuICB9O1xuXG4gIC8qKlxuICAgKiBDaGVja3MgaWYgdGhlIHdhenVoYXBwLmxvZyBmaWxlIHNpemUgaXMgZ3JlYXRlciB0aGFuIDEwME1CLCBpZiBzbyBpdCByb3RhdGVzIHRoZSBmaWxlLlxuICAgKi9cbiAgcHJpdmF0ZSBjaGVja0ZpbGVzID0gKCkgPT4ge1xuICAgIGNyZWF0ZUxvZ0ZpbGVJZk5vdEV4aXN0cyh0aGlzLlJBV19MT0dTX1BBVEgpO1xuICAgIGNyZWF0ZUxvZ0ZpbGVJZk5vdEV4aXN0cyh0aGlzLlBMQUlOX0xPR1NfUEFUSCk7XG4gICAgaWYgKHRoaXMuYWxsb3dlZCkge1xuICAgICAgLy8gY2hlY2sgcmF3IGxvZyBmaWxlXG4gICAgICB0aGlzLnJvdGF0ZUZpbGVzKFxuICAgICAgICB0aGlzLlJBV19MT0dTX0ZJTEVfTkFNRSxcbiAgICAgICAgdGhpcy5SQVdfTE9HU19QQVRILFxuICAgICAgICBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgZGF0ZTogbmV3IERhdGUoKSxcbiAgICAgICAgICBsZXZlbDogJ2luZm8nLFxuICAgICAgICAgIGxvY2F0aW9uOiAnbG9nZ2VyJyxcbiAgICAgICAgICBtZXNzYWdlOiAnUm90YXRlZCBsb2cgZmlsZScsXG4gICAgICAgIH0pXG4gICAgICApO1xuICAgICAgLy8gY2hlY2sgbG9nIGZpbGVcbiAgICAgIHRoaXMucm90YXRlRmlsZXModGhpcy5QTEFJTl9MT0dTX0ZJTEVfTkFNRSwgdGhpcy5QTEFJTl9MT0dTX1BBVEgpO1xuICAgIH1cbiAgfTtcblxuICAvKipcbiAgICogR2V0IEN1cnJlbnQgRGF0ZVxuICAgKiBAcmV0dXJucyBzdHJpbmdcbiAgICovXG4gIHByaXZhdGUgeXl5eW1tZGQgPSAoKSA9PiB7XG4gICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcbiAgICBjb25zdCB5ID0gbm93LmdldEZ1bGxZZWFyKCk7XG4gICAgY29uc3QgbSA9IG5vdy5nZXRNb250aCgpICsgMTtcbiAgICBjb25zdCBkID0gbm93LmdldERhdGUoKTtcbiAgICBjb25zdCBzZWNvbmRzID0gbm93LmdldFNlY29uZHMoKTtcbiAgICBjb25zdCBtaW51dGVzID0gbm93LmdldE1pbnV0ZXMoKTtcbiAgICBjb25zdCBob3VyID0gbm93LmdldEhvdXJzKCk7XG4gICAgcmV0dXJuIGAke3l9LyR7bSA8IDEwID8gJzAnIDogJyd9JHttfS8ke2QgPCAxMCA/ICcwJyA6ICcnfSR7ZH0gJHtob3VyfToke21pbnV0ZXN9OiR7c2Vjb25kc31gO1xuICB9O1xuXG4gIC8qKlxuICAgKiBUaGlzIGZ1bmN0aW9uIGZpbHRlciBzb21lIGtub3duIGludGVyZmFjZXMgdG8gYXZvaWQgbG9nIGh1ZyBvYmplY3RzXG4gICAqIEBwYXJhbSBkYXRhIHN0cmluZyB8IG9iamVjdFxuICAgKiBAcmV0dXJucyB0aGUgZGF0YSBwYXJzZWRcbiAgICovXG4gIHByaXZhdGUgcGFyc2VEYXRhID0gKGRhdGE6IGFueSkgPT4ge1xuICAgIGxldCBwYXJzZWREYXRhID1cbiAgICAgIGRhdGEgaW5zdGFuY2VvZiBFcnJvclxuICAgICAgICA/IHtcbiAgICAgICAgICAgIG1lc3NhZ2U6IGRhdGEubWVzc2FnZSxcbiAgICAgICAgICAgIHN0YWNrOiBkYXRhLnN0YWNrLFxuICAgICAgICAgIH1cbiAgICAgICAgOiBkYXRhO1xuXG4gICAgLy8gd2hlbiBlcnJvciBpcyBBeGlvc0Vycm9yLCBpdCBleHRlbmRzIGZyb20gRXJyb3JcbiAgICBpZiAoZGF0YS5pc0F4aW9zRXJyb3IpIHtcbiAgICAgIGNvbnN0IHsgY29uZmlnIH0gPSBkYXRhO1xuICAgICAgcGFyc2VkRGF0YSA9IHtcbiAgICAgICAgLi4ucGFyc2VkRGF0YSxcbiAgICAgICAgY29uZmlnOiB7XG4gICAgICAgICAgdXJsOiBjb25maWcudXJsLFxuICAgICAgICAgIG1ldGhvZDogY29uZmlnLm1ldGhvZCxcbiAgICAgICAgICBkYXRhOiBjb25maWcuZGF0YSxcbiAgICAgICAgICBwYXJhbXM6IGNvbmZpZy5wYXJhbXMsXG4gICAgICAgIH0sXG4gICAgICB9O1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgcGFyc2VkRGF0YSA9PT0gJ29iamVjdCcpIHBhcnNlZERhdGEudG9TdHJpbmcgPSAoKSA9PiBKU09OLnN0cmluZ2lmeShwYXJzZWREYXRhKTtcblxuICAgIHJldHVybiBwYXJzZWREYXRhO1xuICB9O1xuXG4gIC8qKlxuICAgKiBNYWluIGZ1bmN0aW9uIHRvIGFkZCBhIG5ldyBsb2dcbiAgICogQHBhcmFtIHsqfSBsb2NhdGlvbiBGaWxlIHdoZXJlIHRoZSBsb2cgaXMgYmVpbmcgdGhyb3duXG4gICAqIEBwYXJhbSB7Kn0gZGF0YSBNZXNzYWdlIG9yIG9iamVjdCB0byBsb2dcbiAgICogQHBhcmFtIHsqfSBsZXZlbCBPcHRpb25hbCwgZGVmYXVsdCBpcyAnZXJyb3InXG4gICAqL1xuICAgYXN5bmMgbG9nKGxvY2F0aW9uOiBzdHJpbmcsIGRhdGE6IGFueSwgbGV2ZWw6IHN0cmluZykge1xuICAgIGNvbnN0IHBhcnNlZERhdGEgPSB0aGlzLnBhcnNlRGF0YShkYXRhKTtcbiAgICByZXR1cm4gdGhpcy5pbml0RGlyZWN0b3J5KClcbiAgICAgIC50aGVuKCgpID0+IHtcbiAgICAgICAgaWYgKHRoaXMuYWxsb3dlZCkge1xuICAgICAgICAgIHRoaXMuY2hlY2tGaWxlcygpO1xuICAgICAgICAgIGNvbnN0IHBsYWluTG9nRGF0YTogSVVJUGxhaW5Mb2dnZXJTZXR0aW5ncyA9IHtcbiAgICAgICAgICAgIGxldmVsOiBsZXZlbCB8fCAnZXJyb3InLFxuICAgICAgICAgICAgbWVzc2FnZTogYCR7dGhpcy55eXl5bW1kZCgpfTogJHtsb2NhdGlvbiB8fCAnVW5rbm93biBvcmlnaW4nfTogJHtcbiAgICAgICAgICAgICAgcGFyc2VkRGF0YS50b1N0cmluZygpIHx8ICdBbiBlcnJvciBvY2N1cnJlZCdcbiAgICAgICAgICAgIH1gLFxuICAgICAgICAgIH07XG5cbiAgICAgICAgICB0aGlzLndhenVoUGxhaW5Mb2dnZXIubG9nKHBsYWluTG9nRGF0YSk7XG5cbiAgICAgICAgICBjb25zdCBsb2dEYXRhOiBJVUlMb2dnZXJTZXR0aW5ncyA9IHtcbiAgICAgICAgICAgIGRhdGU6IG5ldyBEYXRlKCksXG4gICAgICAgICAgICBsZXZlbDogbGV2ZWwgfHwgJ2Vycm9yJyxcbiAgICAgICAgICAgIGxvY2F0aW9uOiBsb2NhdGlvbiB8fCAnVW5rbm93biBvcmlnaW4nLFxuICAgICAgICAgICAgZGF0YTogcGFyc2VkRGF0YSB8fCAnQW4gZXJyb3Igb2NjdXJyZWQnLFxuICAgICAgICAgIH07XG5cbiAgICAgICAgICBpZiAodHlwZW9mIGRhdGEgPT0gJ3N0cmluZycpIHtcbiAgICAgICAgICAgIGxvZ0RhdGEubWVzc2FnZSA9IHBhcnNlZERhdGE7XG4gICAgICAgICAgICBkZWxldGUgbG9nRGF0YS5kYXRhO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHRoaXMud2F6dWhMb2dnZXIubG9nKGxvZ0RhdGEpO1xuICAgICAgICB9XG4gICAgICB9KVxuICAgICAgLmNhdGNoKChlcnJvcikgPT4ge1xuICAgICAgICBjb25zb2xlLmVycm9yKGBDYW5ub3QgY3JlYXRlIHRoZSBsb2dzIGRpcmVjdG9yeSBkdWUgdG86XFxuJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWApO1xuICAgICAgICB0aHJvdyBlcnJvcjtcbiAgICAgIH0pO1xuICB9XG59XG4iXX0=
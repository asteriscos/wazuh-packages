"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.DefaultFactory = void 0;

var _constants = require("../../../../common/constants");

var _md = _interopRequireDefault(require("md5"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

class DefaultFactory {
  constructor() {
    _defineProperty(this, "platform", '');
  }

  async getCurrentUser(request, context) {
    return {
      username: _constants.ELASTIC_NAME,
      authContext: {
        username: _constants.ELASTIC_NAME
      },
      hashUsername: (0, _md.default)(_constants.ELASTIC_NAME)
    };
  }

}

exports.DefaultFactory = DefaultFactory;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImRlZmF1bHQtZmFjdG9yeS50cyJdLCJuYW1lcyI6WyJEZWZhdWx0RmFjdG9yeSIsImdldEN1cnJlbnRVc2VyIiwicmVxdWVzdCIsImNvbnRleHQiLCJ1c2VybmFtZSIsIkVMQVNUSUNfTkFNRSIsImF1dGhDb250ZXh0IiwiaGFzaFVzZXJuYW1lIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBRUE7O0FBQ0E7Ozs7OztBQUVPLE1BQU1BLGNBQU4sQ0FBZ0Q7QUFBQTtBQUFBLHNDQUNsQyxFQURrQztBQUFBOztBQUVqQyxRQUFkQyxjQUFjLENBQUNDLE9BQUQsRUFBdUNDLE9BQXZDLEVBQXVFO0FBQ3pGLFdBQU87QUFDTEMsTUFBQUEsUUFBUSxFQUFFQyx1QkFETDtBQUVMQyxNQUFBQSxXQUFXLEVBQUU7QUFBRUYsUUFBQUEsUUFBUSxFQUFFQztBQUFaLE9BRlI7QUFHTEUsTUFBQUEsWUFBWSxFQUFFLGlCQUFJRix1QkFBSjtBQUhULEtBQVA7QUFLRDs7QUFSb0QiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJU2VjdXJpdHlGYWN0b3J5IH0gZnJvbSAnLi4vJztcbmltcG9ydCB7IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVxdWVzdCwgUmVxdWVzdEhhbmRsZXJDb250ZXh0IH0gZnJvbSAnc3JjL2NvcmUvc2VydmVyJztcbmltcG9ydCB7IEVMQVNUSUNfTkFNRSB9IGZyb20gJy4uLy4uLy4uLy4uL2NvbW1vbi9jb25zdGFudHMnO1xuaW1wb3J0IG1kNSBmcm9tICdtZDUnO1xuXG5leHBvcnQgY2xhc3MgRGVmYXVsdEZhY3RvcnkgaW1wbGVtZW50cyBJU2VjdXJpdHlGYWN0b3J5e1xuICBwbGF0Zm9ybTogc3RyaW5nID0gJyc7XG4gIGFzeW5jIGdldEN1cnJlbnRVc2VyKHJlcXVlc3Q6IE9wZW5TZWFyY2hEYXNoYm9hcmRzUmVxdWVzdCwgY29udGV4dD86UmVxdWVzdEhhbmRsZXJDb250ZXh0KSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIHVzZXJuYW1lOiBFTEFTVElDX05BTUUsXG4gICAgICBhdXRoQ29udGV4dDogeyB1c2VybmFtZTogRUxBU1RJQ19OQU1FIH0sXG4gICAgICBoYXNoVXNlcm5hbWU6IG1kNShFTEFTVElDX05BTUUpXG4gICAgfTtcbiAgfVxufVxuIl19
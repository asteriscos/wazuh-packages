"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ReportPrinter = void 0;

var _fs = _interopRequireDefault(require("fs"));

var _path = _interopRequireDefault(require("path"));

var _printer = _interopRequireDefault(require("pdfmake/src/printer"));

var _clockIconRaw = _interopRequireDefault(require("./clock-icon-raw"));

var _filterIconRaw = _interopRequireDefault(require("./filter-icon-raw"));

var _visualizations = require("../../integration-files/visualizations");

var _logger = require("../logger");

var TimSort = _interopRequireWildcard(require("timsort"));

var _getConfiguration = require("../get-configuration");

var _constants = require("../../../common/constants");

var _settings = require("../../../common/services/settings");

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

const COLORS = {
  PRIMARY: _constants.REPORTS_PRIMARY_COLOR
};

const pageConfiguration = ({
  pathToLogo,
  pageHeader,
  pageFooter
}) => ({
  styles: {
    h1: {
      fontSize: 22,
      monslight: true,
      color: COLORS.PRIMARY
    },
    h2: {
      fontSize: 18,
      monslight: true,
      color: COLORS.PRIMARY
    },
    h3: {
      fontSize: 16,
      monslight: true,
      color: COLORS.PRIMARY
    },
    h4: {
      fontSize: 14,
      monslight: true,
      color: COLORS.PRIMARY
    },
    standard: {
      color: '#333'
    },
    whiteColorFilters: {
      color: '#FFF',
      fontSize: 14
    },
    whiteColor: {
      color: '#FFF'
    }
  },
  pageMargins: [40, 80, 40, 80],
  header: {
    margin: [40, 20, 0, 0],
    columns: [{
      image: _path.default.join(__dirname, `../../../public/assets/${pathToLogo}`),
      fit: [190, 50]
    }, {
      text: pageHeader,
      alignment: 'right',
      margin: [0, 0, 40, 0],
      color: COLORS.PRIMARY,
      width: 'auto'
    }]
  },
  content: [],

  footer(currentPage, pageCount) {
    return {
      columns: [{
        text: pageFooter,
        color: COLORS.PRIMARY,
        margin: [40, 40, 0, 0]
      }, {
        text: 'Page ' + currentPage.toString() + ' of ' + pageCount,
        alignment: 'right',
        margin: [0, 40, 40, 0],
        color: COLORS.PRIMARY,
        width: 'auto'
      }]
    };
  },

  pageBreakBefore(currentNode, followingNodesOnPage) {
    if (currentNode.id && currentNode.id.includes('splitvis')) {
      return followingNodesOnPage.length === 6 || followingNodesOnPage.length === 7;
    }

    if (currentNode.id && currentNode.id.includes('splitsinglevis') || currentNode.id && currentNode.id.includes('singlevis')) {
      return followingNodesOnPage.length === 6;
    }

    return false;
  }

});

const fonts = {
  Roboto: {
    normal: _path.default.join(__dirname, '../../../public/assets/fonts/opensans/OpenSans-Light.ttf'),
    bold: _path.default.join(__dirname, '../../../public/assets/fonts/opensans/OpenSans-Bold.ttf'),
    italics: _path.default.join(__dirname, '../../../public/assets/fonts/opensans/OpenSans-Italic.ttf'),
    bolditalics: _path.default.join(__dirname, '../../../public/assets/fonts/opensans/OpenSans-BoldItalic.ttf'),
    monslight: _path.default.join(__dirname, '../../../public/assets/fonts/opensans/Montserrat-Light.ttf')
  }
};

class ReportPrinter {
  constructor() {
    _defineProperty(this, "_content", void 0);

    _defineProperty(this, "_printer", void 0);

    this._printer = new _printer.default(fonts);
    this._content = [];
  }

  addContent(...content) {
    this._content.push(...content);

    return this;
  }

  addConfigTables(tables) {
    (0, _logger.log)('reporting:renderConfigTables', 'Started to render configuration tables', 'info');
    (0, _logger.log)('reporting:renderConfigTables', `tables: ${tables.length}`, 'debug');

    for (const table of tables) {
      let rowsparsed = table.rows;

      if (Array.isArray(rowsparsed) && rowsparsed.length) {
        const rows = rowsparsed.length > 100 ? rowsparsed.slice(0, 99) : rowsparsed;
        this.addContent({
          text: table.title,
          style: {
            fontSize: 11,
            color: '#000'
          },
          margin: table.title && table.type === 'table' ? [0, 0, 0, 5] : ''
        });

        if (table.title === 'Monitored directories') {
          this.addContent({
            text: 'RT: Real time | WD: Who-data | Per.: Permission | MT: Modification time | SL: Symbolic link | RL: Recursion level',
            style: {
              fontSize: 8,
              color: COLORS.PRIMARY
            },
            margin: [0, 0, 0, 5]
          });
        }

        const full_body = [];
        const modifiedRows = rows.map(row => row.map(cell => ({
          text: cell || '-',
          style: 'standard'
        }))); // for (const row of rows) {
        //   modifiedRows.push(
        //     row.map(cell => ({ text: cell || '-', style: 'standard' }))
        //   );
        // }

        let widths = [];
        widths = Array(table.columns.length - 1).fill('auto');
        widths.push('*');

        if (table.type === 'config') {
          full_body.push(table.columns.map(col => ({
            text: col || '-',
            border: [0, 0, 0, 20],
            fontSize: 0,
            colSpan: 2
          })), ...modifiedRows);
          this.addContent({
            fontSize: 8,
            table: {
              headerRows: 0,
              widths,
              body: full_body,
              dontBreakRows: true
            },
            layout: {
              fillColor: i => i === 0 ? '#fff' : null,
              hLineColor: () => '#D3DAE6',
              hLineWidth: () => 1,
              vLineWidth: () => 0
            }
          });
        } else if (table.type === 'table') {
          full_body.push(table.columns.map(col => ({
            text: col || '-',
            style: 'whiteColor',
            border: [0, 0, 0, 0]
          })), ...modifiedRows);
          this.addContent({
            fontSize: 8,
            table: {
              headerRows: 1,
              widths,
              body: full_body
            },
            layout: {
              fillColor: i => i === 0 ? COLORS.PRIMARY : null,
              hLineColor: () => COLORS.PRIMARY,
              hLineWidth: () => 1,
              vLineWidth: () => 0
            }
          });
        }

        this.addNewLine();
      }

      (0, _logger.log)('reporting:renderConfigTables', `Table rendered`, 'debug');
    }
  }

  addTables(tables) {
    (0, _logger.log)('reporting:renderTables', 'Started to render tables', 'info');
    (0, _logger.log)('reporting:renderTables', `tables: ${tables.length}`, 'debug');

    for (const table of tables) {
      let rowsparsed = [];
      rowsparsed = table.rows;

      if (Array.isArray(rowsparsed) && rowsparsed.length) {
        const rows = rowsparsed.length > 100 ? rowsparsed.slice(0, 99) : rowsparsed;
        this.addContent({
          text: table.title,
          style: 'h3',
          pageBreak: 'before',
          pageOrientation: table.columns.length >= 9 ? 'landscape' : 'portrait'
        });
        this.addNewLine();
        const full_body = [];

        const sortTableRows = (a, b) => parseInt(a[a.length - 1]) < parseInt(b[b.length - 1]) ? 1 : parseInt(a[a.length - 1]) > parseInt(b[b.length - 1]) ? -1 : 0;

        TimSort.sort(rows, sortTableRows);
        const modifiedRows = rows.map(row => row.map(cell => ({
          text: cell || '-',
          style: 'standard'
        }))); // the width of the columns is assigned

        const widths = Array(table.columns.length - 1).fill('auto');
        widths.push('*');
        full_body.push(table.columns.map(col => ({
          text: col || '-',
          style: 'whiteColor',
          border: [0, 0, 0, 0]
        })), ...modifiedRows);
        this.addContent({
          fontSize: 8,
          table: {
            headerRows: 1,
            widths,
            body: full_body
          },
          layout: {
            fillColor: i => i === 0 ? COLORS.PRIMARY : null,
            hLineColor: () => COLORS.PRIMARY,
            hLineWidth: () => 1,
            vLineWidth: () => 0
          }
        });
        this.addNewLine();
        (0, _logger.log)('reporting:renderTables', `Table rendered`, 'debug');
      }
    }
  }

  addTimeRangeAndFilters(from, to, filters, timeZone) {
    (0, _logger.log)('reporting:renderTimeRangeAndFilters', `Started to render the time range and the filters`, 'info');
    (0, _logger.log)('reporting:renderTimeRangeAndFilters', `from: ${from}, to: ${to}, filters: ${filters}, timeZone: ${timeZone}`, 'debug');
    const fromDate = new Date(new Date(from).toLocaleString('en-US', {
      timeZone
    }));
    const toDate = new Date(new Date(to).toLocaleString('en-US', {
      timeZone
    }));
    const str = `${this.formatDate(fromDate)} to ${this.formatDate(toDate)}`;
    this.addContent({
      fontSize: 8,
      table: {
        widths: ['*'],
        body: [[{
          columns: [{
            svg: _clockIconRaw.default,
            width: 10,
            height: 10,
            margin: [40, 5, 0, 0]
          }, {
            text: str || '-',
            margin: [43, 0, 0, 0],
            style: 'whiteColorFilters'
          }]
        }], [{
          columns: [{
            svg: _filterIconRaw.default,
            width: 10,
            height: 10,
            margin: [40, 6, 0, 0]
          }, {
            text: filters || '-',
            margin: [43, 0, 0, 0],
            style: 'whiteColorFilters'
          }]
        }]]
      },
      margin: [-40, 0, -40, 0],
      layout: {
        fillColor: () => COLORS.PRIMARY,
        hLineWidth: () => 0,
        vLineWidth: () => 0
      }
    });
    this.addContent({
      text: '\n'
    });
    (0, _logger.log)('reporting:renderTimeRangeAndFilters', 'Time range and filters rendered', 'debug');
  }

  addVisualizations(visualizations, isAgents, tab) {
    (0, _logger.log)('reporting:renderVisualizations', `${visualizations.length} visualizations for tab ${tab}`, 'info');
    const single_vis = visualizations.filter(item => item.width >= 600);
    const double_vis = visualizations.filter(item => item.width < 600);
    single_vis.forEach(visualization => {
      const title = this.checkTitle(visualization, isAgents, tab);
      this.addContent({
        id: 'singlevis' + title[0]._source.title,
        text: title[0]._source.title,
        style: 'h3'
      });
      this.addContent({
        columns: [{
          image: visualization.element,
          width: 500
        }]
      });
      this.addNewLine();
    });
    let pair = [];

    for (const item of double_vis) {
      pair.push(item);

      if (pair.length === 2) {
        const title_1 = this.checkTitle(pair[0], isAgents, tab);
        const title_2 = this.checkTitle(pair[1], isAgents, tab);
        this.addContent({
          columns: [{
            id: 'splitvis' + title_1[0]._source.title,
            text: title_1[0]._source.title,
            style: 'h3',
            width: 280
          }, {
            id: 'splitvis' + title_2[0]._source.title,
            text: title_2[0]._source.title,
            style: 'h3',
            width: 280
          }]
        });
        this.addContent({
          columns: [{
            image: pair[0].element,
            width: 270
          }, {
            image: pair[1].element,
            width: 270
          }]
        });
        this.addNewLine();
        pair = [];
      }
    }

    if (double_vis.length % 2 !== 0) {
      const item = double_vis[double_vis.length - 1];
      const title = this.checkTitle(item, isAgents, tab);
      this.addContent({
        columns: [{
          id: 'splitsinglevis' + title[0]._source.title,
          text: title[0]._source.title,
          style: 'h3',
          width: 280
        }]
      });
      this.addContent({
        columns: [{
          image: item.element,
          width: 280
        }]
      });
      this.addNewLine();
    }
  }

  formatDate(date) {
    (0, _logger.log)('reporting:formatDate', `Format date ${date}`, 'info');
    const year = date.getFullYear();
    const month = date.getMonth() + 1;
    const day = date.getDate();
    const hours = date.getHours();
    const minutes = date.getMinutes();
    const seconds = date.getSeconds();
    const str = `${year}-${month < 10 ? '0' + month : month}-${day < 10 ? '0' + day : day}T${hours < 10 ? '0' + hours : hours}:${minutes < 10 ? '0' + minutes : minutes}:${seconds < 10 ? '0' + seconds : seconds}`;
    (0, _logger.log)('reporting:formatDate', `str: ${str}`, 'debug');
    return str;
  }

  checkTitle(item, isAgents, tab) {
    (0, _logger.log)('reporting:checkTitle', `Item ID ${item.id}, from ${isAgents ? 'agents' : 'overview'} and tab ${tab}`, 'info');
    const title = isAgents ? _visualizations.AgentsVisualizations[tab].filter(v => v._id === item.id) : _visualizations.OverviewVisualizations[tab].filter(v => v._id === item.id);
    return title;
  }

  addSimpleTable({
    columns,
    items,
    title
  }) {
    if (title) {
      this.addContent(typeof title === 'string' ? {
        text: title,
        style: 'h4'
      } : title).addNewLine();
    }

    if (!items || !items.length) {
      this.addContent({
        text: 'No results match your search criteria',
        style: 'standard'
      });
      return this;
    }

    const tableHeader = columns.map(column => {
      return {
        text: column.label,
        style: 'whiteColor',
        border: [0, 0, 0, 0]
      };
    });
    const tableRows = items.map((item, index) => {
      return columns.map(column => {
        const cellValue = item[column.id];
        return {
          text: typeof cellValue !== 'undefined' ? cellValue : '-',
          style: 'standard'
        };
      });
    }); // 385 is the max initial width per column

    let totalLength = columns.length - 1;
    const widthColumn = 385 / totalLength;
    let totalWidth = totalLength * widthColumn;
    const widths = [];

    for (let step = 0; step < columns.length - 1; step++) {
      let columnLength = this.getColumnWidth(columns[step], tableRows, step);

      if (columnLength <= Math.round(totalWidth / totalLength)) {
        widths.push(columnLength);
        totalWidth -= columnLength;
      } else {
        widths.push(Math.round(totalWidth / totalLength));
        totalWidth -= Math.round(totalWidth / totalLength);
      }

      totalLength--;
    }

    widths.push('*');
    this.addContent({
      fontSize: 8,
      table: {
        headerRows: 1,
        widths,
        body: [tableHeader, ...tableRows]
      },
      layout: {
        fillColor: i => i === 0 ? COLORS.PRIMARY : null,
        hLineColor: () => COLORS.PRIMARY,
        hLineWidth: () => 1,
        vLineWidth: () => 0
      }
    }).addNewLine();
    return this;
  }

  addList({
    title,
    list
  }) {
    return this.addContentWithNewLine(typeof title === 'string' ? {
      text: title,
      style: 'h2'
    } : title).addContent({
      ul: list.filter(element => element)
    }).addNewLine();
  }

  addNewLine() {
    return this.addContent({
      text: '\n'
    });
  }

  addContentWithNewLine(title) {
    return this.addContent(title).addNewLine();
  }

  addAgentsFilters(agents) {
    (0, _logger.log)('reporting:addAgentsFilters', `Started to render the authorized agents filters`, 'info');
    (0, _logger.log)('reporting:addAgentsFilters', `agents: ${agents}`, 'debug');
    this.addNewLine();
    this.addContent({
      text: 'NOTE: This report only includes the authorized agents of the user who generated the report',
      style: {
        fontSize: 10,
        color: COLORS.PRIMARY
      },
      margin: [0, 0, 0, 5]
    });
    /*TODO: This will be enabled by a config*/

    /* this.addContent({
      fontSize: 8,
      table: {
        widths: ['*'],
        body: [
          [
            {
              columns: [
                {
                  svg: filterIconRaw,
                  width: 10,
                  height: 10,
                  margin: [40, 6, 0, 0]
                },
                {
                  text: `Agent IDs: ${agents}` || '-',
                  margin: [43, 0, 0, 0],
                  style: { fontSize: 8, color: '#333' }
                }
              ]
            }
          ]
        ]
      },
      margin: [-40, 0, -40, 0],
      layout: {
        fillColor: () => null,
        hLineWidth: () => 0,
        vLineWidth: () => 0
      }
    }); */

    this.addContent({
      text: '\n'
    });
    (0, _logger.log)('reporting:addAgentsFilters', 'Time range and filters rendered', 'debug');
  }

  async print(reportPath) {
    return new Promise((resolve, reject) => {
      try {
        const configuration = (0, _getConfiguration.getConfiguration)();
        const pathToLogo = (0, _settings.getCustomizationSetting)(configuration, 'customization.logo.reports');
        const pageHeader = (0, _settings.getCustomizationSetting)(configuration, 'customization.reports.header');
        const pageFooter = (0, _settings.getCustomizationSetting)(configuration, 'customization.reports.footer');

        const document = this._printer.createPdfKitDocument({ ...pageConfiguration({
            pathToLogo,
            pageHeader,
            pageFooter
          }),
          content: this._content
        });

        document.on('error', reject);
        document.on('end', resolve);
        document.pipe(_fs.default.createWriteStream(reportPath));
        document.end();
      } catch (ex) {
        reject(ex);
      }
    });
  }
  /**
   * Returns the width of a given column
   *
   * @param column
   * @param tableRows
   * @param step
   * @returns {number}
   */


  getColumnWidth(column, tableRows, index) {
    const widthCharacter = 5; //min width per character
    //Get the longest row value

    const maxRowLength = tableRows.reduce((maxLength, row) => {
      return row[index].text.length > maxLength ? row[index].text.length : maxLength;
    }, 0); //Get column name length

    const headerLength = column.label.length; //Use the longest to get the column width

    const maxLength = maxRowLength > headerLength ? maxRowLength : headerLength;
    return maxLength * widthCharacter;
  }

}

exports.ReportPrinter = ReportPrinter;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInByaW50ZXIudHMiXSwibmFtZXMiOlsiQ09MT1JTIiwiUFJJTUFSWSIsIlJFUE9SVFNfUFJJTUFSWV9DT0xPUiIsInBhZ2VDb25maWd1cmF0aW9uIiwicGF0aFRvTG9nbyIsInBhZ2VIZWFkZXIiLCJwYWdlRm9vdGVyIiwic3R5bGVzIiwiaDEiLCJmb250U2l6ZSIsIm1vbnNsaWdodCIsImNvbG9yIiwiaDIiLCJoMyIsImg0Iiwic3RhbmRhcmQiLCJ3aGl0ZUNvbG9yRmlsdGVycyIsIndoaXRlQ29sb3IiLCJwYWdlTWFyZ2lucyIsImhlYWRlciIsIm1hcmdpbiIsImNvbHVtbnMiLCJpbWFnZSIsInBhdGgiLCJqb2luIiwiX19kaXJuYW1lIiwiZml0IiwidGV4dCIsImFsaWdubWVudCIsIndpZHRoIiwiY29udGVudCIsImZvb3RlciIsImN1cnJlbnRQYWdlIiwicGFnZUNvdW50IiwidG9TdHJpbmciLCJwYWdlQnJlYWtCZWZvcmUiLCJjdXJyZW50Tm9kZSIsImZvbGxvd2luZ05vZGVzT25QYWdlIiwiaWQiLCJpbmNsdWRlcyIsImxlbmd0aCIsImZvbnRzIiwiUm9ib3RvIiwibm9ybWFsIiwiYm9sZCIsIml0YWxpY3MiLCJib2xkaXRhbGljcyIsIlJlcG9ydFByaW50ZXIiLCJjb25zdHJ1Y3RvciIsIl9wcmludGVyIiwiUGRmUHJpbnRlciIsIl9jb250ZW50IiwiYWRkQ29udGVudCIsInB1c2giLCJhZGRDb25maWdUYWJsZXMiLCJ0YWJsZXMiLCJ0YWJsZSIsInJvd3NwYXJzZWQiLCJyb3dzIiwiQXJyYXkiLCJpc0FycmF5Iiwic2xpY2UiLCJ0aXRsZSIsInN0eWxlIiwidHlwZSIsImZ1bGxfYm9keSIsIm1vZGlmaWVkUm93cyIsIm1hcCIsInJvdyIsImNlbGwiLCJ3aWR0aHMiLCJmaWxsIiwiY29sIiwiYm9yZGVyIiwiY29sU3BhbiIsImhlYWRlclJvd3MiLCJib2R5IiwiZG9udEJyZWFrUm93cyIsImxheW91dCIsImZpbGxDb2xvciIsImkiLCJoTGluZUNvbG9yIiwiaExpbmVXaWR0aCIsInZMaW5lV2lkdGgiLCJhZGROZXdMaW5lIiwiYWRkVGFibGVzIiwicGFnZUJyZWFrIiwicGFnZU9yaWVudGF0aW9uIiwic29ydFRhYmxlUm93cyIsImEiLCJiIiwicGFyc2VJbnQiLCJUaW1Tb3J0Iiwic29ydCIsImFkZFRpbWVSYW5nZUFuZEZpbHRlcnMiLCJmcm9tIiwidG8iLCJmaWx0ZXJzIiwidGltZVpvbmUiLCJmcm9tRGF0ZSIsIkRhdGUiLCJ0b0xvY2FsZVN0cmluZyIsInRvRGF0ZSIsInN0ciIsImZvcm1hdERhdGUiLCJzdmciLCJjbG9ja0ljb25SYXciLCJoZWlnaHQiLCJmaWx0ZXJJY29uUmF3IiwiYWRkVmlzdWFsaXphdGlvbnMiLCJ2aXN1YWxpemF0aW9ucyIsImlzQWdlbnRzIiwidGFiIiwic2luZ2xlX3ZpcyIsImZpbHRlciIsIml0ZW0iLCJkb3VibGVfdmlzIiwiZm9yRWFjaCIsInZpc3VhbGl6YXRpb24iLCJjaGVja1RpdGxlIiwiX3NvdXJjZSIsImVsZW1lbnQiLCJwYWlyIiwidGl0bGVfMSIsInRpdGxlXzIiLCJkYXRlIiwieWVhciIsImdldEZ1bGxZZWFyIiwibW9udGgiLCJnZXRNb250aCIsImRheSIsImdldERhdGUiLCJob3VycyIsImdldEhvdXJzIiwibWludXRlcyIsImdldE1pbnV0ZXMiLCJzZWNvbmRzIiwiZ2V0U2Vjb25kcyIsIkFnZW50c1Zpc3VhbGl6YXRpb25zIiwidiIsIl9pZCIsIk92ZXJ2aWV3VmlzdWFsaXphdGlvbnMiLCJhZGRTaW1wbGVUYWJsZSIsIml0ZW1zIiwidGFibGVIZWFkZXIiLCJjb2x1bW4iLCJsYWJlbCIsInRhYmxlUm93cyIsImluZGV4IiwiY2VsbFZhbHVlIiwidG90YWxMZW5ndGgiLCJ3aWR0aENvbHVtbiIsInRvdGFsV2lkdGgiLCJzdGVwIiwiY29sdW1uTGVuZ3RoIiwiZ2V0Q29sdW1uV2lkdGgiLCJNYXRoIiwicm91bmQiLCJhZGRMaXN0IiwibGlzdCIsImFkZENvbnRlbnRXaXRoTmV3TGluZSIsInVsIiwiYWRkQWdlbnRzRmlsdGVycyIsImFnZW50cyIsInByaW50IiwicmVwb3J0UGF0aCIsIlByb21pc2UiLCJyZXNvbHZlIiwicmVqZWN0IiwiY29uZmlndXJhdGlvbiIsImRvY3VtZW50IiwiY3JlYXRlUGRmS2l0RG9jdW1lbnQiLCJvbiIsInBpcGUiLCJmcyIsImNyZWF0ZVdyaXRlU3RyZWFtIiwiZW5kIiwiZXgiLCJ3aWR0aENoYXJhY3RlciIsIm1heFJvd0xlbmd0aCIsInJlZHVjZSIsIm1heExlbmd0aCIsImhlYWRlckxlbmd0aCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUlBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOzs7Ozs7Ozs7O0FBRUEsTUFBTUEsTUFBTSxHQUFHO0FBQ2JDLEVBQUFBLE9BQU8sRUFBRUM7QUFESSxDQUFmOztBQUlBLE1BQU1DLGlCQUFpQixHQUFHLENBQUM7QUFBRUMsRUFBQUEsVUFBRjtBQUFjQyxFQUFBQSxVQUFkO0FBQTBCQyxFQUFBQTtBQUExQixDQUFELE1BQTZDO0FBQ3JFQyxFQUFBQSxNQUFNLEVBQUU7QUFDTkMsSUFBQUEsRUFBRSxFQUFFO0FBQ0ZDLE1BQUFBLFFBQVEsRUFBRSxFQURSO0FBRUZDLE1BQUFBLFNBQVMsRUFBRSxJQUZUO0FBR0ZDLE1BQUFBLEtBQUssRUFBRVgsTUFBTSxDQUFDQztBQUhaLEtBREU7QUFNTlcsSUFBQUEsRUFBRSxFQUFFO0FBQ0ZILE1BQUFBLFFBQVEsRUFBRSxFQURSO0FBRUZDLE1BQUFBLFNBQVMsRUFBRSxJQUZUO0FBR0ZDLE1BQUFBLEtBQUssRUFBRVgsTUFBTSxDQUFDQztBQUhaLEtBTkU7QUFXTlksSUFBQUEsRUFBRSxFQUFFO0FBQ0ZKLE1BQUFBLFFBQVEsRUFBRSxFQURSO0FBRUZDLE1BQUFBLFNBQVMsRUFBRSxJQUZUO0FBR0ZDLE1BQUFBLEtBQUssRUFBRVgsTUFBTSxDQUFDQztBQUhaLEtBWEU7QUFnQk5hLElBQUFBLEVBQUUsRUFBRTtBQUNGTCxN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dEMsVUFBTThCLGNBQWMsR0FBRyxDQUF2QixDQURzQyxDQUNaO0FBRTFCOztBQUNBLFVBQU1DLFlBQVksR0FBR2hDLFNBQVMsQ0FBQ2lDLE1BQVYsQ0FBaUIsQ0FBQ0MsU0FBRCxFQUFZakgsR0FBWixLQUFrQjtBQUN0RCxhQUFRQSxHQUFHLENBQUNnRixLQUFELENBQUgsQ0FBV3pILElBQVgsQ0FBZ0JhLE1BQWhCLEdBQXlCNkksU0FBekIsR0FBcUNqSCxHQUFHLENBQUNnRixLQUFELENBQUgsQ0FBV3pILElBQVgsQ0FBZ0JhLE1BQXJELEdBQThENkksU0FBdEU7QUFDRCxLQUZvQixFQUVuQixDQUZtQixDQUFyQixDQUpzQyxDQVF0Qzs7QUFDQSxVQUFNQyxZQUFZLEdBQUdyQyxNQUFNLENBQUNDLEtBQVAsQ0FBYTFHLE1BQWxDLENBVHNDLENBV3RDOztBQUNBLFVBQU02SSxTQUFTLEdBQUdGLFlBQVksR0FBR0csWUFBZixHQUE4QkgsWUFBOUIsR0FBNkNHLFlBQS9EO0FBRUEsV0FBT0QsU0FBUyxHQUFHSCxjQUFuQjtBQUNEOztBQXZoQnVCIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IGZzIGZyb20gJ2ZzJztcbmltcG9ydCBwYXRoIGZyb20gJ3BhdGgnO1xuaW1wb3J0IFBkZlByaW50ZXIgZnJvbSAncGRmbWFrZS9zcmMvcHJpbnRlcic7XG5pbXBvcnQgY2xvY2tJY29uUmF3IGZyb20gJy4vY2xvY2staWNvbi1yYXcnO1xuaW1wb3J0IGZpbHRlckljb25SYXcgZnJvbSAnLi9maWx0ZXItaWNvbi1yYXcnO1xuaW1wb3J0IHtcbiAgQWdlbnRzVmlzdWFsaXphdGlvbnMsXG4gIE92ZXJ2aWV3VmlzdWFsaXphdGlvbnNcbn0gZnJvbSAnLi4vLi4vaW50ZWdyYXRpb24tZmlsZXMvdmlzdWFsaXphdGlvbnMnO1xuaW1wb3J0IHsgbG9nIH0gZnJvbSAnLi4vbG9nZ2VyJztcbmltcG9ydCAqIGFzIFRpbVNvcnQgZnJvbSAndGltc29ydCc7XG5pbXBvcnQgeyBnZXRDb25maWd1cmF0aW9uIH0gZnJvbSAnLi4vZ2V0LWNvbmZpZ3VyYXRpb24nO1xuaW1wb3J0IHsgUkVQT1JUU19QUklNQVJZX0NPTE9SfSBmcm9tICcuLi8uLi8uLi9jb21tb24vY29uc3RhbnRzJztcbmltcG9ydCB7IGdldEN1c3RvbWl6YXRpb25TZXR0aW5nIH0gZnJvbSAnLi4vLi4vLi4vY29tbW9uL3NlcnZpY2VzL3NldHRpbmdzJztcblxuY29uc3QgQ09MT1JTID0ge1xuICBQUklNQVJZOiBSRVBPUlRTX1BSSU1BUllfQ09MT1Jcbn07XG5cbmNvbnN0IHBhZ2VDb25maWd1cmF0aW9uID0gKHsgcGF0aFRvTG9nbywgcGFnZUhlYWRlciwgcGFnZUZvb3RlciB9KSA9PiAoe1xuICBzdHlsZXM6IHtcbiAgICBoMToge1xuICAgICAgZm9udFNpemU6IDIyLFxuICAgICAgbW9uc2xpZ2h0OiB0cnVlLFxuICAgICAgY29sb3I6IENPTE9SUy5QUklNQVJZXG4gICAgfSxcbiAgICBoMjoge1xuICAgICAgZm9udFNpemU6IDE4LFxuICAgICAgbW9uc2xpZ2h0OiB0cnVlLFxuICAgICAgY29sb3I6IENPTE9SUy5QUklNQVJZXG4gICAgfSxcbiAgICBoMzoge1xuICAgICAgZm9udFNpemU6IDE2LFxuICAgICAgbW9uc2xpZ2h0OiB0cnVlLFxuICAgICAgY29sb3I6IENPTE9SUy5QUklNQVJZXG4gICAgfSxcbiAgICBoNDoge1xuICAgICAgZm9udFNpemU6IDE0LFxuICAgICAgbW9uc2xpZ2h0OiB0cnVlLFxuICAgICAgY29sb3I6IENPTE9SUy5QUklNQVJZXG4gICAgfSxcbiAgICBzdGFuZGFyZDoge1xuICAgICAgY29sb3I6ICcjMzMzJ1xuICAgIH0sXG4gICAgd2hpdGVDb2xvckZpbHRlcnM6IHtcbiAgICAgIGNvbG9yOiAnI0ZGRicsXG4gICAgICBmb250U2l6ZTogMTRcbiAgICB9LFxuICAgIHdoaXRlQ29sb3I6IHtcbiAgICAgIGNvbG9yOiAnI0ZGRidcbiAgICB9XG4gIH0sXG4gIHBhZ2VNYXJnaW5zOiBbNDAsIDgwLCA0MCwgODBdLFxuICBoZWFkZXI6IHtcbiAgICBtYXJnaW46IFs0MCwgMjAsIDAsIDBdLFxuICAgIGNvbHVtbnM6IFtcbiAgICAgIHtcbiAgICAgICAgaW1hZ2U6IHBhdGguam9pbihfX2Rpcm5hbWUsIGAuLi8uLi8uLi9wdWJsaWMvYXNzZXRzLyR7cGF0aFRvTG9nb31gKSxcbiAgICAgICAgZml0OiBbMTkwLCA1MF1cbiAgICAgIH0sXG4gICAgICB7XG4gICAgICAgIHRleHQ6IHBhZ2VIZWFkZXIsXG4gICAgICAgIGFsaWdubWVudDogJ3JpZ2h0JyxcbiAgICAgICAgbWFyZ2luOiBbMCwgMCwgNDAsIDBdLFxuICAgICAgICBjb2xvcjogQ09MT1JTLlBSSU1BUlksXG4gICAgICAgIHdpZHRoOiAnYXV0bydcbiAgICAgIH1cbiAgICBdXG4gIH0sXG4gIGNvbnRlbnQ6IFtdLFxuICBmb290ZXIoY3VycmVudFBhZ2UsIHBhZ2VDb3VudCkge1xuICAgIHJldHVybiB7XG4gICAgICBjb2x1bW5zOiBbXG4gICAgICAgIHtcbiAgICAgICAgICB0ZXh0OiBwYWdlRm9vdGVyLFxuICAgICAgICAgIGNvbG9yOiBDT0xPUlMuUFJJTUFSWSxcbiAgICAgICAgICBtYXJnaW46IFs0MCwgNDAsIDAsIDBdXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICB0ZXh0OiAnUGFnZSAnICsgY3VycmVudFBhZ2UudG9TdHJpbmcoKSArICcgb2YgJyArIHBhZ2VDb3VudCxcbiAgICAgICAgICBhbGlnbm1lbnQ6ICdyaWdodCcsXG4gICAgICAgICAgbWFyZ2luOiBbMCwgNDAsIDQwLCAwXSxcbiAgICAgICAgICBjb2xvcjogQ09MT1JTLlBSSU1BUlksXG4gICAgICAgICAgd2lkdGg6ICdhdXRvJ1xuICAgICAgICB9XG4gICAgICBdXG4gICAgfTtcbiAgfSxcbiAgcGFnZUJyZWFrQmVmb3JlKGN1cnJlbnROb2RlLCBmb2xsb3dpbmdOb2Rlc09uUGFnZSkge1xuICAgIGlmIChjdXJyZW50Tm9kZS5pZCAmJiBjdXJyZW50Tm9kZS5pZC5pbmNsdWRlcygnc3BsaXR2aXMnKSkge1xuICAgICAgcmV0dXJuIChcbiAgICAgICAgZm9sbG93aW5nTm9kZXNPblBhZ2UubGVuZ3RoID09PSA2IHx8XG4gICAgICAgIGZvbGxvd2luZ05vZGVzT25QYWdlLmxlbmd0aCA9PT0gN1xuICAgICAgKTtcbiAgICB9XG4gICAgaWYgKFxuICAgICAgKGN1cnJlbnROb2RlLmlkICYmIGN1cnJlbnROb2RlLmlkLmluY2x1ZGVzKCdzcGxpdHNpbmdsZXZpcycpKSB8fFxuICAgICAgKGN1cnJlbnROb2RlLmlkICYmIGN1cnJlbnROb2RlLmlkLmluY2x1ZGVzKCdzaW5nbGV2aXMnKSlcbiAgICApIHtcbiAgICAgIHJldHVybiBmb2xsb3dpbmdOb2Rlc09uUGFnZS5sZW5ndGggPT09IDY7XG4gICAgfVxuICAgIHJldHVybiBmYWxzZTtcbiAgfVxufSk7XG5cbmNvbnN0IGZvbnRzID0ge1xuICBSb2JvdG86IHtcbiAgICBub3JtYWw6IHBhdGguam9pbihcbiAgICAgIF9fZGlybmFtZSxcbiAgICAgICcuLi8uLi8uLi9wdWJsaWMvYXNzZXRzL2ZvbnRzL29wZW5zYW5zL09wZW5TYW5zLUxpZ2h0LnR0ZidcbiAgICApLFxuICAgIGJvbGQ6IHBhdGguam9pbihcbiAgICAgIF9fZGlybmFtZSxcbiAgICAgICcuLi8uLi8uLi9wdWJsaWMvYXNzZXRzL2ZvbnRzL29wZW5zYW5zL09wZW5TYW5zLUJvbGQudHRmJ1xuICAgICksXG4gICAgaXRhbGljczogcGF0aC5qb2luKFxuICAgICAgX19kaXJuYW1lLFxuICAgICAgJy4uLy4uLy4uL3B1YmxpYy9hc3NldHMvZm9udHMvb3BlbnNhbnMvT3BlblNhbnMtSXRhbGljLnR0ZidcbiAgICApLFxuICAgIGJvbGRpdGFsaWNzOiBwYXRoLmpvaW4oXG4gICAgICBfX2Rpcm5hbWUsXG4gICAgICAnLi4vLi4vLi4vcHVibGljL2Fzc2V0cy9mb250cy9vcGVuc2Fucy9PcGVuU2Fucy1Cb2xkSXRhbGljLnR0ZidcbiAgICApLFxuICAgIG1vbnNsaWdodDogcGF0aC5qb2luKFxuICAgICAgX19kaXJuYW1lLFxuICAgICAgJy4uLy4uLy4uL3B1YmxpYy9hc3NldHMvZm9udHMvb3BlbnNhbnMvTW9udHNlcnJhdC1MaWdodC50dGYnXG4gICAgKVxuICB9XG59O1xuXG5leHBvcnQgY2xhc3MgUmVwb3J0UHJpbnRlcntcbiAgcHJpdmF0ZSBfY29udGVudDogYW55W107XG4gIHByaXZhdGUgX3ByaW50ZXI6IFBkZlByaW50ZXI7XG4gIGNvbnN0cnVjdG9yKCl7XG4gICAgdGhpcy5fcHJpbnRlciA9IG5ldyBQZGZQcmludGVyKGZvbnRzKTtcbiAgICB0aGlzLl9jb250ZW50ID0gW107XG4gIH1cbiAgYWRkQ29udGVudCguLi5jb250ZW50OiBhbnkpe1xuICAgIHRoaXMuX2NvbnRlbnQucHVzaCguLi5jb250ZW50KTtcbiAgICByZXR1cm4gdGhpcztcbiAgfVxuICBhZGRDb25maWdUYWJsZXModGFibGVzOiBhbnkpe1xuICAgIGxvZyhcbiAgICAgICdyZXBvcnRpbmc6cmVuZGVyQ29uZmlnVGFibGVzJyxcbiAgICAgICdTdGFydGVkIHRvIHJlbmRlciBjb25maWd1cmF0aW9uIHRhYmxlcycsXG4gICAgICAnaW5mbydcbiAgICApO1xuICAgIGxvZygncmVwb3J0aW5nOnJlbmRlckNvbmZpZ1RhYmxlcycsIGB0YWJsZXM6ICR7dGFibGVzLmxlbmd0aH1gLCAnZGVidWcnKTtcbiAgICBmb3IgKGNvbnN0IHRhYmxlIG9mIHRhYmxlcykge1xuICAgICAgbGV0IHJvd3NwYXJzZWQgPSB0YWJsZS5yb3dzO1xuICAgICAgaWYgKEFycmF5LmlzQXJyYXkocm93c3BhcnNlZCkgJiYgcm93c3BhcnNlZC5sZW5ndGgpIHtcbiAgICAgICAgY29uc3Qgcm93cyA9XG4gICAgICAgICAgcm93c3BhcnNlZC5sZW5ndGggPiAxMDAgPyByb3dzcGFyc2VkLnNsaWNlKDAsIDk5KSA6IHJvd3NwYXJzZWQ7XG4gICAgICAgIHRoaXMuYWRkQ29udGVudCh7XG4gICAgICAgICAgdGV4dDogdGFibGUudGl0bGUsXG4gICAgICAgICAgc3R5bGU6IHsgZm9udFNpemU6IDExLCBjb2xvcjogJyMwMDAnIH0sXG4gICAgICAgICAgbWFyZ2luOiB0YWJsZS50aXRsZSAmJiB0YWJsZS50eXBlID09PSAndGFibGUnID8gWzAsIDAsIDAsIDVdIDogJydcbiAgICAgICAgfSk7XG5cbiAgICAgICAgaWYgKHRhYmxlLnRpdGxlID09PSAnTW9uaXRvcmVkIGRpcmVjdG9yaWVzJykge1xuICAgICAgICAgIHRoaXMuYWRkQ29udGVudCh7XG4gICAgICAgICAgICB0ZXh0OlxuICAgICAgICAgICAgICAnUlQ6IFJlYWwgdGltZSB8IFdEOiBXaG8tZGF0YSB8IFBlci46IFBlcm1pc3Npb24gfCBNVDogTW9kaWZpY2F0aW9uIHRpbWUgfCBTTDogU3ltYm9saWMgbGluayB8IFJMOiBSZWN1cnNpb24gbGV2ZWwnLFxuICAgICAgICAgICAgc3R5bGU6IHsgZm9udFNpemU6IDgsIGNvbG9yOiBDT0xPUlMuUFJJTUFSWSB9LFxuICAgICAgICAgICAgbWFyZ2luOiBbMCwgMCwgMCwgNV1cbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGZ1bGxfYm9keSA9IFtdO1xuXG4gICAgICAgIGNvbnN0IG1vZGlmaWVkUm93cyA9IHJvd3MubWFwKHJvdyA9PiByb3cubWFwKGNlbGwgPT4gKHsgdGV4dDogY2VsbCB8fCAnLScsIHN0eWxlOiAnc3RhbmRhcmQnIH0pKSk7XG4gICAgICAgIC8vIGZvciAoY29uc3Qgcm93IG9mIHJvd3MpIHtcbiAgICAgICAgLy8gICBtb2RpZmllZFJvd3MucHVzaChcbiAgICAgICAgLy8gICAgIHJvdy5tYXAoY2VsbCA9PiAoeyB0ZXh0OiBjZWxsIHx8ICctJywgc3R5bGU6ICdzdGFuZGFyZCcgfSkpXG4gICAgICAgIC8vICAgKTtcbiAgICAgICAgLy8gfVxuICAgICAgICBsZXQgd2lkdGhzID0gW107XG4gICAgICAgIHdpZHRocyA9IEFycmF5KHRhYmxlLmNvbHVtbnMubGVuZ3RoIC0gMSkuZmlsbCgnYXV0bycpO1xuICAgICAgICB3aWR0aHMucHVzaCgnKicpO1xuXG4gICAgICAgIGlmICh0YWJsZS50eXBlID09PSAnY29uZmlnJykge1xuICAgICAgICAgIGZ1bGxfYm9keS5wdXNoKFxuICAgICAgICAgICAgdGFibGUuY29sdW1ucy5tYXAoY29sID0+ICh7XG4gICAgICAgICAgICAgIHRleHQ6IGNvbCB8fCAnLScsXG4gICAgICAgICAgICAgIGJvcmRlcjogWzAsIDAsIDAsIDIwXSxcbiAgICAgICAgICAgICAgZm9udFNpemU6IDAsXG4gICAgICAgICAgICAgIGNvbFNwYW46IDJcbiAgICAgICAgICAgIH0pKSxcbiAgICAgICAgICAgIC4uLm1vZGlmaWVkUm93c1xuICAgICAgICAgICk7XG4gICAgICAgICAgdGhpcy5hZGRDb250ZW50KHtcbiAgICAgICAgICAgIGZvbnRTaXplOiA4LFxuICAgICAgICAgICAgdGFibGU6IHtcbiAgICAgICAgICAgICAgaGVhZGVyUm93czogMCxcbiAgICAgICAgICAgICAgd2lkdGhzLFxuICAgICAgICAgICAgICBib2R5OiBmdWxsX2JvZHksXG4gICAgICAgICAgICAgIGRvbnRCcmVha1Jvd3M6IHRydWVcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBsYXlvdXQ6IHtcbiAgICAgICAgICAgICAgZmlsbENvbG9yOiBpID0+IChpID09PSAwID8gJyNmZmYnIDogbnVsbCksXG4gICAgICAgICAgICAgIGhMaW5lQ29sb3I6ICgpID0+ICcjRDNEQUU2JyxcbiAgICAgICAgICAgICAgaExpbmVXaWR0aDogKCkgPT4gMSxcbiAgICAgICAgICAgICAgdkxpbmVXaWR0aDogKCkgPT4gMFxuICAgICAgICAgICAgfVxuICAgICAgICAgIH0pO1xuICAgICAgICB9IGVsc2UgaWYgKHRhYmxlLnR5cGUgPT09ICd0YWJsZScpIHtcbiAgICAgICAgICBmdWxsX2JvZHkucHVzaChcbiAgICAgICAgICAgIHRhYmxlLmNvbHVtbnMubWFwKGNvbCA9PiAoe1xuICAgICAgICAgICAgICB0ZXh0OiBjb2wgfHwgJy0nLFxuICAgICAgICAgICAgICBzdHlsZTogJ3doaXRlQ29sb3InLFxuICAgICAgICAgICAgICBib3JkZXI6IFswLCAwLCAwLCAwXVxuICAgICAgICAgICAgfSkpLFxuICAgICAgICAgICAgLi4ubW9kaWZpZWRSb3dzXG4gICAgICAgICAgKTtcbiAgICAgICAgICB0aGlzLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgZm9udFNpemU6IDgsXG4gICAgICAgICAgICB0YWJsZToge1xuICAgICAgICAgICAgICBoZWFkZXJSb3dzOiAxLFxuICAgICAgICAgICAgICB3aWR0aHMsXG4gICAgICAgICAgICAgIGJvZHk6IGZ1bGxfYm9keVxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIGxheW91dDoge1xuICAgICAgICAgICAgICBmaWxsQ29sb3I6IGkgPT4gKGkgPT09IDAgPyBDT0xPUlMuUFJJTUFSWSA6IG51bGwpLFxuICAgICAgICAgICAgICBoTGluZUNvbG9yOiAoKSA9PiBDT0xPUlMuUFJJTUFSWSxcbiAgICAgICAgICAgICAgaExpbmVXaWR0aDogKCkgPT4gMSxcbiAgICAgICAgICAgICAgdkxpbmVXaWR0aDogKCkgPT4gMFxuICAgICAgICAgICAgfVxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuYWRkTmV3TGluZSgpO1xuICAgICAgfVxuICAgICAgbG9nKCdyZXBvcnRpbmc6cmVuZGVyQ29uZmlnVGFibGVzJywgYFRhYmxlIHJlbmRlcmVkYCwgJ2RlYnVnJyk7XG4gICAgfVxuICB9XG5cbiAgYWRkVGFibGVzKHRhYmxlczogYW55KXtcbiAgICBsb2coJ3JlcG9ydGluZzpyZW5kZXJUYWJsZXMnLCAnU3RhcnRlZCB0byByZW5kZXIgdGFibGVzJywgJ2luZm8nKTtcbiAgICBsb2coJ3JlcG9ydGluZzpyZW5kZXJUYWJsZXMnLCBgdGFibGVzOiAke3RhYmxlcy5sZW5ndGh9YCwgJ2RlYnVnJyk7XG4gICAgZm9yIChjb25zdCB0YWJsZSBvZiB0YWJsZXMpIHtcbiAgICAgIGxldCByb3dzcGFyc2VkID0gW107XG4gICAgICByb3dzcGFyc2VkID0gdGFibGUucm93cztcbiAgICAgIGlmIChBcnJheS5pc0FycmF5KHJvd3NwYXJzZWQpICYmIHJvd3NwYXJzZWQubGVuZ3RoKSB7XG4gICAgICAgIGNvbnN0IHJvd3MgPVxuICAgICAgICAgIHJvd3NwYXJzZWQubGVuZ3RoID4gMTAwID8gcm93c3BhcnNlZC5zbGljZSgwLCA5OSkgOiByb3dzcGFyc2VkO1xuICAgICAgICB0aGlzLmFkZENvbnRlbnQoe1xuICAgICAgICAgIHRleHQ6IHRhYmxlLnRpdGxlLFxuICAgICAgICAgIHN0eWxlOiAnaDMnLFxuICAgICAgICAgIHBhZ2VCcmVhazogJ2JlZm9yZScsXG4gICAgICAgICAgcGFnZU9yaWVudGF0aW9uOiB0YWJsZS5jb2x1bW5zLmxlbmd0aCA+PSA5ID8gJ2xhbmRzY2FwZScgOiAncG9ydHJhaXQnLFxuICAgICAgICB9KTtcbiAgICAgICAgdGhpcy5hZGROZXdMaW5lKCk7XG4gICAgICAgIGNvbnN0IGZ1bGxfYm9keSA9IFtdO1xuICAgICAgICBjb25zdCBzb3J0VGFibGVSb3dzID0gKGEsIGIpID0+XG4gICAgICAgICAgcGFyc2VJbnQoYVthLmxlbmd0aCAtIDFdKSA8IHBhcnNlSW50KGJbYi5sZW5ndGggLSAxXSlcbiAgICAgICAgICAgID8gMVxuICAgICAgICAgICAgOiBwYXJzZUludChhW2EubGVuZ3RoIC0gMV0pID4gcGFyc2VJbnQoYltiLmxlbmd0aCAtIDFdKVxuICAgICAgICAgICAgPyAtMVxuICAgICAgICAgICAgOiAwO1xuXG4gICAgICAgIFRpbVNvcnQuc29ydChyb3dzLCBzb3J0VGFibGVSb3dzKTtcblxuICAgICAgICBjb25zdCBtb2RpZmllZFJvd3MgPSByb3dzLm1hcChyb3cgPT4gcm93Lm1hcChjZWxsID0+ICh7IHRleHQ6IGNlbGwgfHwgJy0nLCBzdHlsZTogJ3N0YW5kYXJkJyB9KSkpO1xuXG4gICAgICAgIC8vIHRoZSB3aWR0aCBvZiB0aGUgY29sdW1ucyBpcyBhc3NpZ25lZFxuICAgICAgICBjb25zdCB3aWR0aHMgPSBBcnJheSh0YWJsZS5jb2x1bW5zLmxlbmd0aCAtIDEpLmZpbGwoJ2F1dG8nKTtcbiAgICAgICAgd2lkdGhzLnB1c2goJyonKTtcblxuICAgICAgICBmdWxsX2JvZHkucHVzaChcbiAgICAgICAgICB0YWJsZS5jb2x1bW5zLm1hcChjb2wgPT4gKHtcbiAgICAgICAgICAgIHRleHQ6IGNvbCB8fCAnLScsXG4gICAgICAgICAgICBzdHlsZTogJ3doaXRlQ29sb3InLFxuICAgICAgICAgICAgYm9yZGVyOiBbMCwgMCwgMCwgMF1cbiAgICAgICAgICB9KSksXG4gICAgICAgICAgLi4ubW9kaWZpZWRSb3dzXG4gICAgICAgICk7XG4gICAgICAgIHRoaXMuYWRkQ29udGVudCh7XG4gICAgICAgICAgZm9udFNpemU6IDgsXG4gICAgICAgICAgdGFibGU6IHtcbiAgICAgICAgICAgIGhlYWRlclJvd3M6IDEsXG4gICAgICAgICAgICB3aWR0aHMsXG4gICAgICAgICAgICBib2R5OiBmdWxsX2JvZHlcbiAgICAgICAgICB9LFxuICAgICAgICAgIGxheW91dDoge1xuICAgICAgICAgICAgZmlsbENvbG9yOiBpID0+IChpID09PSAwID8gQ09MT1JTLlBSSU1BUlkgOiBudWxsKSxcbiAgICAgICAgICAgIGhMaW5lQ29sb3I6ICgpID0+IENPTE9SUy5QUklNQVJZLFxuICAgICAgICAgICAgaExpbmVXaWR0aDogKCkgPT4gMSxcbiAgICAgICAgICAgIHZMaW5lV2lkdGg6ICgpID0+IDBcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgICB0aGlzLmFkZE5ld0xpbmUoKTtcbiAgICAgICAgbG9nKCdyZXBvcnRpbmc6cmVuZGVyVGFibGVzJywgYFRhYmxlIHJlbmRlcmVkYCwgJ2RlYnVnJyk7XG4gICAgICB9XG4gICAgfVxuICB9XG4gIGFkZFRpbWVSYW5nZUFuZEZpbHRlcnMoZnJvbSwgdG8sIGZpbHRlcnMsIHRpbWVab25lKXtcbiAgICBsb2coXG4gICAgICAncmVwb3J0aW5nOnJlbmRlclRpbWVSYW5nZUFuZEZpbHRlcnMnLFxuICAgICAgYFN0YXJ0ZWQgdG8gcmVuZGVyIHRoZSB0aW1lIHJhbmdlIGFuZCB0aGUgZmlsdGVyc2AsXG4gICAgICAnaW5mbydcbiAgICApO1xuICAgIGxvZyhcbiAgICAgICdyZXBvcnRpbmc6cmVuZGVyVGltZVJhbmdlQW5kRmlsdGVycycsXG4gICAgICBgZnJvbTogJHtmcm9tfSwgdG86ICR7dG99LCBmaWx0ZXJzOiAke2ZpbHRlcnN9LCB0aW1lWm9uZTogJHt0aW1lWm9uZX1gLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG4gICAgY29uc3QgZnJvbURhdGUgPSBuZXcgRGF0ZShcbiAgICAgIG5ldyBEYXRlKGZyb20pLnRvTG9jYWxlU3RyaW5nKCdlbi1VUycsIHsgdGltZVpvbmUgfSlcbiAgICApO1xuICAgIGNvbnN0IHRvRGF0ZSA9IG5ldyBEYXRlKG5ldyBEYXRlKHRvKS50b0xvY2FsZVN0cmluZygnZW4tVVMnLCB7IHRpbWVab25lIH0pKTtcbiAgICBjb25zdCBzdHIgPSBgJHt0aGlzLmZvcm1hdERhdGUoZnJvbURhdGUpfSB0byAke3RoaXMuZm9ybWF0RGF0ZSh0b0RhdGUpfWA7XG5cbiAgICB0aGlzLmFkZENvbnRlbnQoe1xuICAgICAgZm9udFNpemU6IDgsXG4gICAgICB0YWJsZToge1xuICAgICAgICB3aWR0aHM6IFsnKiddLFxuICAgICAgICBib2R5OiBbXG4gICAgICAgICAgW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBjb2x1bW5zOiBbXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgc3ZnOiBjbG9ja0ljb25SYXcsXG4gICAgICAgICAgICAgICAgICB3aWR0aDogMTAsXG4gICAgICAgICAgICAgICAgICBoZWlnaHQ6IDEwLFxuICAgICAgICAgICAgICAgICAgbWFyZ2luOiBbNDAsIDUsIDAsIDBdXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICB0ZXh0OiBzdHIgfHwgJy0nLFxuICAgICAgICAgICAgICAgICAgbWFyZ2luOiBbNDMsIDAsIDAsIDBdLFxuICAgICAgICAgICAgICAgICAgc3R5bGU6ICd3aGl0ZUNvbG9yRmlsdGVycydcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIF1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICBdLFxuICAgICAgICAgIFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgIHN2ZzogZmlsdGVySWNvblJhdyxcbiAgICAgICAgICAgICAgICAgIHdpZHRoOiAxMCxcbiAgICAgICAgICAgICAgICAgIGhlaWdodDogMTAsXG4gICAgICAgICAgICAgICAgICBtYXJnaW46IFs0MCwgNiwgMCwgMF1cbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgIHRleHQ6IGZpbHRlcnMgfHwgJy0nLFxuICAgICAgICAgICAgICAgICAgbWFyZ2luOiBbNDMsIDAsIDAsIDBdLFxuICAgICAgICAgICAgICAgICAgc3R5bGU6ICd3aGl0ZUNvbG9yRmlsdGVycydcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIF1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICBdXG4gICAgICAgIF1cbiAgICAgIH0sXG4gICAgICBtYXJnaW46IFstNDAsIDAsIC00MCwgMF0sXG4gICAgICBsYXlvdXQ6IHtcbiAgICAgICAgZmlsbENvbG9yOiAoKSA9PiBDT0xPUlMuUFJJTUFSWSxcbiAgICAgICAgaExpbmVXaWR0aDogKCkgPT4gMCxcbiAgICAgICAgdkxpbmVXaWR0aDogKCkgPT4gMFxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgdGhpcy5hZGRDb250ZW50KHsgdGV4dDogJ1xcbicgfSk7XG4gICAgbG9nKFxuICAgICAgJ3JlcG9ydGluZzpyZW5kZXJUaW1lUmFuZ2VBbmRGaWx0ZXJzJyxcbiAgICAgICdUaW1lIHJhbmdlIGFuZCBmaWx0ZXJzIHJlbmRlcmVkJyxcbiAgICAgICdkZWJ1ZydcbiAgICApO1xuICB9XG4gIGFkZFZpc3VhbGl6YXRpb25zKHZpc3VhbGl6YXRpb25zLCBpc0FnZW50cywgdGFiKXtcbiAgICBsb2coXG4gICAgICAncmVwb3J0aW5nOnJlbmRlclZpc3VhbGl6YXRpb25zJyxcbiAgICAgIGAke3Zpc3VhbGl6YXRpb25zLmxlbmd0aH0gdmlzdWFsaXphdGlvbnMgZm9yIHRhYiAke3RhYn1gLFxuICAgICAgJ2luZm8nXG4gICAgKTtcbiAgICBjb25zdCBzaW5nbGVfdmlzID0gdmlzdWFsaXphdGlvbnMuZmlsdGVyKGl0ZW0gPT4gaXRlbS53aWR0aCA+PSA2MDApO1xuICAgIGNvbnN0IGRvdWJsZV92aXMgPSB2aXN1YWxpemF0aW9ucy5maWx0ZXIoaXRlbSA9PiBpdGVtLndpZHRoIDwgNjAwKTtcblxuICAgIHNpbmdsZV92aXMuZm9yRWFjaCh2aXN1YWxpemF0aW9uID0+IHtcbiAgICAgIGNvbnN0IHRpdGxlID0gdGhpcy5jaGVja1RpdGxlKHZpc3VhbGl6YXRpb24sIGlzQWdlbnRzLCB0YWIpO1xuICAgICAgdGhpcy5hZGRDb250ZW50KHtcbiAgICAgICAgaWQ6ICdzaW5nbGV2aXMnICsgdGl0bGVbMF0uX3NvdXJjZS50aXRsZSxcbiAgICAgICAgdGV4dDogdGl0bGVbMF0uX3NvdXJjZS50aXRsZSxcbiAgICAgICAgc3R5bGU6ICdoMydcbiAgICAgIH0pO1xuICAgICAgdGhpcy5hZGRDb250ZW50KHsgY29sdW1uczogW3sgaW1hZ2U6IHZpc3VhbGl6YXRpb24uZWxlbWVudCwgd2lkdGg6IDUwMCB9XSB9KTtcbiAgICAgIHRoaXMuYWRkTmV3TGluZSgpO1xuICAgIH0pXG5cbiAgICBsZXQgcGFpciA9IFtdO1xuXG4gICAgZm9yIChjb25zdCBpdGVtIG9mIGRvdWJsZV92aXMpIHtcbiAgICAgIHBhaXIucHVzaChpdGVtKTtcbiAgICAgIGlmIChwYWlyLmxlbmd0aCA9PT0gMikge1xuICAgICAgICBjb25zdCB0aXRsZV8xID0gdGhpcy5jaGVja1RpdGxlKHBhaXJbMF0sIGlzQWdlbnRzLCB0YWIpO1xuICAgICAgICBjb25zdCB0aXRsZV8yID0gdGhpcy5jaGVja1RpdGxlKHBhaXJbMV0sIGlzQWdlbnRzLCB0YWIpO1xuXG4gICAgICAgIHRoaXMuYWRkQ29udGVudCh7XG4gICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ3NwbGl0dmlzJyArIHRpdGxlXzFbMF0uX3NvdXJjZS50aXRsZSxcbiAgICAgICAgICAgICAgdGV4dDogdGl0bGVfMVswXS5fc291cmNlLnRpdGxlLFxuICAgICAgICAgICAgICBzdHlsZTogJ2gzJyxcbiAgICAgICAgICAgICAgd2lkdGg6IDI4MFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdzcGxpdHZpcycgKyB0aXRsZV8yWzBdLl9zb3VyY2UudGl0bGUsXG4gICAgICAgICAgICAgIHRleHQ6IHRpdGxlXzJbMF0uX3NvdXJjZS50aXRsZSxcbiAgICAgICAgICAgICAgc3R5bGU6ICdoMycsXG4gICAgICAgICAgICAgIHdpZHRoOiAyODBcbiAgICAgICAgICAgIH1cbiAgICAgICAgICBdXG4gICAgICAgIH0pO1xuXG4gICAgICAgIHRoaXMuYWRkQ29udGVudCh7XG4gICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgeyBpbWFnZTogcGFpclswXS5lbGVtZW50LCB3aWR0aDogMjcwIH0sXG4gICAgICAgICAgICB7IGltYWdlOiBwYWlyWzFdLmVsZW1lbnQsIHdpZHRoOiAyNzAgfVxuICAgICAgICAgIF1cbiAgICAgICAgfSk7XG5cbiAgICAgICAgdGhpcy5hZGROZXdMaW5lKCk7XG4gICAgICAgIHBhaXIgPSBbXTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAoZG91YmxlX3Zpcy5sZW5ndGggJSAyICE9PSAwKSB7XG4gICAgICBjb25zdCBpdGVtID0gZG91YmxlX3Zpc1tkb3VibGVfdmlzLmxlbmd0aCAtIDFdO1xuICAgICAgY29uc3QgdGl0bGUgPSB0aGlzLmNoZWNrVGl0bGUoaXRlbSwgaXNBZ2VudHMsIHRhYik7XG4gICAgICB0aGlzLmFkZENvbnRlbnQoe1xuICAgICAgICBjb2x1bW5zOiBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICdzcGxpdHNpbmdsZXZpcycgKyB0aXRsZVswXS5fc291cmNlLnRpdGxlLFxuICAgICAgICAgICAgdGV4dDogdGl0bGVbMF0uX3NvdXJjZS50aXRsZSxcbiAgICAgICAgICAgIHN0eWxlOiAnaDMnLFxuICAgICAgICAgICAgd2lkdGg6IDI4MFxuICAgICAgICAgIH1cbiAgICAgICAgXVxuICAgICAgfSk7XG4gICAgICB0aGlzLmFkZENvbnRlbnQoeyBjb2x1bW5zOiBbeyBpbWFnZTogaXRlbS5lbGVtZW50LCB3aWR0aDogMjgwIH1dIH0pO1xuICAgICAgdGhpcy5hZGROZXdMaW5lKCk7XG4gICAgfVxuICB9XG4gIGZvcm1hdERhdGUoZGF0ZTogRGF0ZSk6IHN0cmluZyB7XG4gICAgbG9nKCdyZXBvcnRpbmc6Zm9ybWF0RGF0ZScsIGBGb3JtYXQgZGF0ZSAke2RhdGV9YCwgJ2luZm8nKTtcbiAgICBjb25zdCB5ZWFyID0gZGF0ZS5nZXRGdWxsWWVhcigpO1xuICAgIGNvbnN0IG1vbnRoID0gZGF0ZS5nZXRNb250aCgpICsgMTtcbiAgICBjb25zdCBkYXkgPSBkYXRlLmdldERhdGUoKTtcbiAgICBjb25zdCBob3VycyA9IGRhdGUuZ2V0SG91cnMoKTtcbiAgICBjb25zdCBtaW51dGVzID0gZGF0ZS5nZXRNaW51dGVzKCk7XG4gICAgY29uc3Qgc2Vjb25kcyA9IGRhdGUuZ2V0U2Vjb25kcygpO1xuICAgIGNvbnN0IHN0ciA9IGAke3llYXJ9LSR7bW9udGggPCAxMCA/ICcwJyArIG1vbnRoIDogbW9udGh9LSR7XG4gICAgICBkYXkgPCAxMCA/ICcwJyArIGRheSA6IGRheVxuICAgIH1UJHtob3VycyA8IDEwID8gJzAnICsgaG91cnMgOiBob3Vyc306JHtcbiAgICAgIG1pbnV0ZXMgPCAxMCA/ICcwJyArIG1pbnV0ZXMgOiBtaW51dGVzXG4gICAgfToke3NlY29uZHMgPCAxMCA/ICcwJyArIHNlY29uZHMgOiBzZWNvbmRzfWA7XG4gICAgbG9nKCdyZXBvcnRpbmc6Zm9ybWF0RGF0ZScsIGBzdHI6ICR7c3RyfWAsICdkZWJ1ZycpO1xuICAgIHJldHVybiBzdHI7XG4gIH1cbiAgY2hlY2tUaXRsZShpdGVtLCBpc0FnZW50cywgdGFiKSB7XG4gICAgbG9nKFxuICAgICAgJ3JlcG9ydGluZzpjaGVja1RpdGxlJyxcbiAgICAgIGBJdGVtIElEICR7aXRlbS5pZH0sIGZyb20gJHtcbiAgICAgICAgaXNBZ2VudHMgPyAnYWdlbnRzJyA6ICdvdmVydmlldydcbiAgICAgIH0gYW5kIHRhYiAke3RhYn1gLFxuICAgICAgJ2luZm8nXG4gICAgKTtcblxuICAgIGNvbnN0IHRpdGxlID0gaXNBZ2VudHNcbiAgICAgID8gQWdlbnRzVmlzdWFsaXphdGlvbnNbdGFiXS5maWx0ZXIodiA9PiB2Ll9pZCA9PT0gaXRlbS5pZClcbiAgICAgIDogT3ZlcnZpZXdWaXN1YWxpemF0aW9uc1t0YWJdLmZpbHRlcih2ID0+IHYuX2lkID09PSBpdGVtLmlkKTtcbiAgICByZXR1cm4gdGl0bGU7XG4gIH1cblxuICBhZGRTaW1wbGVUYWJsZSh7Y29sdW1ucywgaXRlbXMsIHRpdGxlfToge2NvbHVtbnM6ICh7aWQ6IHN0cmluZywgbGFiZWw6IHN0cmluZ30pW10sIHRpdGxlPzogKHN0cmluZyB8IHt0ZXh0OiBzdHJpbmcsIHN0eWxlOiBzdHJpbmd9KSwgaXRlbXM6IGFueVtdfSl7XG5cbiAgICBpZiAodGl0bGUpIHtcbiAgICAgIHRoaXMuYWRkQ29udGVudCh0eXBlb2YgdGl0bGUgPT09ICdzdHJpbmcnID8geyB0ZXh0OiB0aXRsZSwgc3R5bGU6ICdoNCcgfSA6IHRpdGxlKVxuICAgICAgICAuYWRkTmV3TGluZSgpO1xuICAgIH1cblxuICAgIGlmICghaXRlbXMgfHwgIWl0ZW1zLmxlbmd0aCkge1xuICAgICAgdGhpcy5hZGRDb250ZW50KHtcbiAgICAgICAgdGV4dDogJ05vIHJlc3VsdHMgbWF0Y2ggeW91ciBzZWFyY2ggY3JpdGVyaWEnLFxuICAgICAgICBzdHlsZTogJ3N0YW5kYXJkJ1xuICAgICAgfSk7XG4gICAgICByZXR1cm4gdGhpcztcbiAgICB9XG5cbiAgICBjb25zdCB0YWJsZUhlYWRlciA9IGNvbHVtbnMubWFwKGNvbHVtbiA9PiB7XG4gICAgICByZXR1cm4geyB0ZXh0OiBjb2x1bW4ubGFiZWwsIHN0eWxlOiAnd2hpdGVDb2xvcicsIGJvcmRlcjogWzAsIDAsIDAsIDBdIH07XG4gICAgfSk7XG5cbiAgICBjb25zdCB0YWJsZVJvd3MgPSBpdGVtcy5tYXAoKGl0ZW0sIGluZGV4KSA9PiB7XG4gICAgICByZXR1cm4gY29sdW1ucy5tYXAoY29sdW1uID0+IHtcbiAgICAgICAgY29uc3QgY2VsbFZhbHVlID0gaXRlbVtjb2x1bW4uaWRdO1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgIHRleHQ6IHR5cGVvZiBjZWxsVmFsdWUgIT09ICd1bmRlZmluZWQnID8gY2VsbFZhbHVlIDogJy0nLFxuICAgICAgICAgIHN0eWxlOiAnc3RhbmRhcmQnXG4gICAgICAgIH1cbiAgICAgIH0pXG4gICAgfSk7XG5cbiAgICAvLyAzODUgaXMgdGhlIG1heCBpbml0aWFsIHdpZHRoIHBlciBjb2x1bW5cbiAgICBsZXQgdG90YWxMZW5ndGggPSBjb2x1bW5zLmxlbmd0aCAtIDE7XG4gICAgY29uc3Qgd2lkdGhDb2x1bW4gPSAzODUvdG90YWxMZW5ndGg7XG4gICAgbGV0IHRvdGFsV2lkdGggPSB0b3RhbExlbmd0aCAqIHdpZHRoQ29sdW1uO1xuXG4gICAgY29uc3Qgd2lkdGhzOihudW1iZXIpW10gPSBbXTtcblxuICAgIGZvciAobGV0IHN0ZXAgPSAwOyBzdGVwIDwgY29sdW1ucy5sZW5ndGggLSAxOyBzdGVwKyspIHtcblxuICAgICAgbGV0IGNvbHVtbkxlbmd0aCA9IHRoaXMuZ2V0Q29sdW1uV2lkdGgoY29sdW1uc1tzdGVwXSwgdGFibGVSb3dzLCBzdGVwKTtcblxuICAgICAgaWYgKGNvbHVtbkxlbmd0aCA8PSBNYXRoLnJvdW5kKHRvdGFsV2lkdGggLyB0b3RhbExlbmd0aCkpIHtcbiAgICAgICAgd2lkdGhzLnB1c2goY29sdW1uTGVuZ3RoKTtcbiAgICAgICAgdG90YWxXaWR0aCAtPSBjb2x1bW5MZW5ndGg7XG4gICAgICB9XG4gICAgICBlbHNlIHtcbiAgICAgICAgd2lkdGhzLnB1c2goTWF0aC5yb3VuZCh0b3RhbFdpZHRoIC8gdG90YWxMZW5ndGgpKTtcbiAgICAgICAgdG90YWxXaWR0aCAtPSBNYXRoLnJvdW5kKCh0b3RhbFdpZHRoIC8gdG90YWxMZW5ndGgpKTtcbiAgICAgIH1cbiAgICAgIHRvdGFsTGVuZ3RoLS07XG4gICAgfVxuICAgIHdpZHRocy5wdXNoKCcqJyk7XG5cbiAgICB0aGlzLmFkZENvbnRlbnQoe1xuICAgICAgZm9udFNpemU6IDgsXG4gICAgICB0YWJsZToge1xuICAgICAgICBoZWFkZXJSb3dzOiAxLFxuICAgICAgICB3aWR0aHMsXG4gICAgICAgIGJvZHk6IFt0YWJsZUhlYWRlciwgLi4udGFibGVSb3dzXVxuICAgICAgfSxcbiAgICAgIGxheW91dDoge1xuICAgICAgICBmaWxsQ29sb3I6IGkgPT4gKGkgPT09IDAgPyBDT0xPUlMuUFJJTUFSWSA6IG51bGwpLFxuICAgICAgICBoTGluZUNvbG9yOiAoKSA9PiBDT0xPUlMuUFJJTUFSWSxcbiAgICAgICAgaExpbmVXaWR0aDogKCkgPT4gMSxcbiAgICAgICAgdkxpbmVXaWR0aDogKCkgPT4gMFxuICAgICAgfVxuICAgIH0pLmFkZE5ld0xpbmUoKTtcbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIGFkZExpc3Qoe3RpdGxlLCBsaXN0fToge3RpdGxlOiBzdHJpbmcgfCB7dGV4dDogc3RyaW5nLCBzdHlsZTogc3RyaW5nfSwgbGlzdDogKHN0cmluZyB8IHt0ZXh0OiBzdHJpbmcsIHN0eWxlOiBzdHJpbmd9KVtdfSl7XG4gICAgcmV0dXJuIHRoaXNcbiAgICAgIC5hZGRDb250ZW50V2l0aE5ld0xpbmUodHlwZW9mIHRpdGxlID09PSAnc3RyaW5nJyA/IHt0ZXh0OiB0aXRsZSwgc3R5bGU6ICdoMid9IDogdGl0bGUpXG4gICAgICAuYWRkQ29udGVudCh7dWw6IGxpc3QuZmlsdGVyKGVsZW1lbnQgPT4gZWxlbWVudCl9KVxuICAgICAgLmFkZE5ld0xpbmUoKTtcbiAgfVxuXG4gIGFkZE5ld0xpbmUoKXtcbiAgICByZXR1cm4gdGhpcy5hZGRDb250ZW50KHt0ZXh0OiAnXFxuJ30pO1xuICB9XG5cbiAgYWRkQ29udGVudFdpdGhOZXdMaW5lKHRpdGxlOiBhbnkpe1xuICAgIHJldHVybiB0aGlzLmFkZENvbnRlbnQodGl0bGUpLmFkZE5ld0xpbmUoKTtcbiAgfVxuXG4gIGFkZEFnZW50c0ZpbHRlcnMoYWdlbnRzKXtcbiAgICBsb2coXG4gICAgICAncmVwb3J0aW5nOmFkZEFnZW50c0ZpbHRlcnMnLFxuICAgICAgYFN0YXJ0ZWQgdG8gcmVuZGVyIHRoZSBhdXRob3JpemVkIGFnZW50cyBmaWx0ZXJzYCxcbiAgICAgICdpbmZvJ1xuICAgICk7XG4gICAgbG9nKFxuICAgICAgJ3JlcG9ydGluZzphZGRBZ2VudHNGaWx0ZXJzJyxcbiAgICAgIGBhZ2VudHM6ICR7YWdlbnRzfWAsXG4gICAgICAnZGVidWcnXG4gICAgKTtcblxuICAgIHRoaXMuYWRkTmV3TGluZSgpO1xuXG4gICAgdGhpcy5hZGRDb250ZW50KHtcbiAgICAgIHRleHQ6XG4gICAgICAgICdOT1RFOiBUaGlzIHJlcG9ydCBvbmx5IGluY2x1ZGVzIHRoZSBhdXRob3JpemVkIGFnZW50cyBvZiB0aGUgdXNlciB3aG8gZ2VuZXJhdGVkIHRoZSByZXBvcnQnLFxuICAgICAgc3R5bGU6IHsgZm9udFNpemU6IDEwLCBjb2xvcjogQ09MT1JTLlBSSU1BUlkgfSxcbiAgICAgIG1hcmdpbjogWzAsIDAsIDAsIDVdXG4gICAgfSk7XG5cbiAgICAvKlRPRE86IFRoaXMgd2lsbCBiZSBlbmFibGVkIGJ5IGEgY29uZmlnKi9cbiAgICAvKiB0aGlzLmFkZENvbnRlbnQoe1xuICAgICAgZm9udFNpemU6IDgsXG4gICAgICB0YWJsZToge1xuICAgICAgICB3aWR0aHM6IFsnKiddLFxuICAgICAgICBib2R5OiBbXG4gICAgICAgICAgW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBjb2x1bW5zOiBbXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgc3ZnOiBmaWx0ZXJJY29uUmF3LFxuICAgICAgICAgICAgICAgICAgd2lkdGg6IDEwLFxuICAgICAgICAgICAgICAgICAgaGVpZ2h0OiAxMCxcbiAgICAgICAgICAgICAgICAgIG1hcmdpbjogWzQwLCA2LCAwLCAwXVxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgdGV4dDogYEFnZW50IElEczogJHthZ2VudHN9YCB8fCAnLScsXG4gICAgICAgICAgICAgICAgICBtYXJnaW46IFs0MywgMCwgMCwgMF0sXG4gICAgICAgICAgICAgICAgICBzdHlsZTogeyBmb250U2l6ZTogOCwgY29sb3I6ICcjMzMzJyB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBdXG4gICAgICAgICAgICB9XG4gICAgICAgICAgXVxuICAgICAgICBdXG4gICAgICB9LFxuICAgICAgbWFyZ2luOiBbLTQwLCAwLCAtNDAsIDBdLFxuICAgICAgbGF5b3V0OiB7XG4gICAgICAgIGZpbGxDb2xvcjogKCkgPT4gbnVsbCxcbiAgICAgICAgaExpbmVXaWR0aDogKCkgPT4gMCxcbiAgICAgICAgdkxpbmVXaWR0aDogKCkgPT4gMFxuICAgICAgfVxuICAgIH0pOyAqL1xuXG4gICAgdGhpcy5hZGRDb250ZW50KHsgdGV4dDogJ1xcbicgfSk7XG4gICAgbG9nKFxuICAgICAgJ3JlcG9ydGluZzphZGRBZ2VudHNGaWx0ZXJzJyxcbiAgICAgICdUaW1lIHJhbmdlIGFuZCBmaWx0ZXJzIHJlbmRlcmVkJyxcbiAgICAgICdkZWJ1ZydcbiAgICApO1xuICB9XG5cbiAgYXN5bmMgcHJpbnQocmVwb3J0UGF0aDogc3RyaW5nKSB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGNvbmZpZ3VyYXRpb24gPSBnZXRDb25maWd1cmF0aW9uKCk7XG5cbiAgICAgICAgY29uc3QgcGF0aFRvTG9nbyA9IGdldEN1c3RvbWl6YXRpb25TZXR0aW5nKGNvbmZpZ3VyYXRpb24sICdjdXN0b21pemF0aW9uLmxvZ28ucmVwb3J0cycpO1xuICAgICAgICBjb25zdCBwYWdlSGVhZGVyID0gZ2V0Q3VzdG9taXphdGlvblNldHRpbmcoY29uZmlndXJhdGlvbiwgJ2N1c3RvbWl6YXRpb24ucmVwb3J0cy5oZWFkZXInKTtcbiAgICAgICAgY29uc3QgcGFnZUZvb3RlciA9IGdldEN1c3RvbWl6YXRpb25TZXR0aW5nKGNvbmZpZ3VyYXRpb24sICdjdXN0b21pemF0aW9uLnJlcG9ydHMuZm9vdGVyJyk7XG5cbiAgICAgICAgY29uc3QgZG9jdW1lbnQgPSB0aGlzLl9wcmludGVyLmNyZWF0ZVBkZktpdERvY3VtZW50KHsgLi4ucGFnZUNvbmZpZ3VyYXRpb24oeyBwYXRoVG9Mb2dvLCBwYWdlSGVhZGVyLCBwYWdlRm9vdGVyIH0pLCBjb250ZW50OiB0aGlzLl9jb250ZW50IH0pO1xuXG4gICAgICAgIGRvY3VtZW50Lm9uKCdlcnJvcicsIHJlamVjdCk7XG4gICAgICAgIGRvY3VtZW50Lm9uKCdlbmQnLCByZXNvbHZlKTtcblxuICAgICAgICBkb2N1bWVudC5waXBlKFxuICAgICAgICAgIGZzLmNyZWF0ZVdyaXRlU3RyZWFtKHJlcG9ydFBhdGgpXG4gICAgICAgICk7XG4gICAgICAgIGRvY3VtZW50LmVuZCgpO1xuICAgICAgfSBjYXRjaCAoZXgpIHtcbiAgICAgICAgcmVqZWN0KGV4KTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIHRoZSB3aWR0aCBvZiBhIGdpdmVuIGNvbHVtblxuICAgKlxuICAgKiBAcGFyYW0gY29sdW1uXG4gICAqIEBwYXJhbSB0YWJsZVJvd3NcbiAgICogQHBhcmFtIHN0ZXBcbiAgICogQHJldHVybnMge251bWJlcn1cbiAgICovXG4gIGdldENvbHVtbldpZHRoKGNvbHVtbiwgdGFibGVSb3dzLCBpbmRleCl7XG4gICAgY29uc3Qgd2lkdGhDaGFyYWN0ZXIgPSA1OyAvL21pbiB3aWR0aCBwZXIgY2hhcmFjdGVyXG5cbiAgICAvL0dldCB0aGUgbG9uZ2VzdCByb3cgdmFsdWVcbiAgICBjb25zdCBtYXhSb3dMZW5ndGggPSB0YWJsZVJvd3MucmVkdWNlKChtYXhMZW5ndGgsIHJvdyk9PntcbiAgICAgIHJldHVybiAocm93W2luZGV4XS50ZXh0Lmxlbmd0aCA+IG1heExlbmd0aCA/IHJvd1tpbmRleF0udGV4dC5sZW5ndGggOiBtYXhMZW5ndGgpO1xuICAgIH0sMCk7XG5cbiAgICAvL0dldCBjb2x1bW4gbmFtZSBsZW5ndGhcbiAgICBjb25zdCBoZWFkZXJMZW5ndGggPSBjb2x1bW4ubGFiZWwubGVuZ3RoO1xuXG4gICAgLy9Vc2UgdGhlIGxvbmdlc3QgdG8gZ2V0IHRoZSBjb2x1bW4gd2lkdGhcbiAgICBjb25zdCBtYXhMZW5ndGggPSBtYXhSb3dMZW5ndGggPiBoZWFkZXJMZW5ndGggPyBtYXhSb3dMZW5ndGggOiBoZWFkZXJMZW5ndGg7XG5cbiAgICByZXR1cm4gbWF4TGVuZ3RoICogd2lkdGhDaGFyYWN0ZXI7XG4gIH1cbn1cbiJdfQ==
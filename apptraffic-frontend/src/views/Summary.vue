<template>
  <b-container>
    <componentHeader :title="'Summary of session ' + getSessionName()" />
    <div v-show="loading">
      <b-row>
        <b-col col xs="12" sm="1"
          ><b-spinner style="spinner" label="Loading"></b-spinner
        ></b-col>
        <b-col sx="12" sm="auto"
          >Please be patient. &nbsp;It may take a short while to generate the
          summary.</b-col
        >
      </b-row>
    </div>
    <div v-show="loaded">
      <div class="mb-3">
        <table class="table table-sm table-borderless">
          <tbody>
            <tr>
              <th>Started</th>
              <td class="text-left">
                {{ getSessionStartTime }}
              </td>
            </tr>
            <tr>
              <th>Ended</th>
              <td>{{ getSessionEndTime }}</td>
            </tr>
            <tr>
              <th>Mode</th>
              <td>{{ humaniseText(sessionSummary.intercept_mode) }}</td>
            </tr>
            <tr>
              <th>Entry point</th>
              <td>{{ sessionSummary.entry_node_name }}</td>
            </tr>
            <tr>
              <th>Exit point</th>
              <td>{{ sessionSummary.exit_node_name }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-show="loaded && !sessionSummary.analysis_generated">
        Details about the session are not available at the moment. Perhaps the
        data are being transferred to the storage service. Please try again
        later. &#x231b;
      </div>
      <div v-show="sessionSummary.analysis_generated" class="mb-3">
        <b-icon icon="box-arrow-right" class="mr-2"></b-icon> Export
        <a href="#" @click.prevent="exportHostCount" class="ml-4"
          ><b-icon icon="file-earmark-spreadsheet"></b-icon> Hostname counts</a
        >
        <a href="#" @click.prevent="exportDataValues" class="ml-4"
          ><b-icon icon="file-earmark-spreadsheet"></b-icon> Data values</a
        >
      </div>
      <div v-show="sessionSummary.analysis_generated">
        <div>
          <h4>HTTP hostnames</h4>
          <b-table
            :items="sessionSummary.hosts"
            :fields="['host', 'count', 'tracker']"
            table-variant="secondary"
            head-variant="dark"
            sticky-header
            small
            striped
          >
            <template v-slot:cell(host)="cellData">
              <textarea
                readonly
                rows="1"
                class="form-control-plaintext"
                wrap="soft"
                v-model="cellData.value"
              ></textarea>
            </template>
          </b-table>
        </div>
        <h4>HTTP request headers</h4>
        <b-table
          :items="sessionSummary.request_headers"
          :fields="['name', 'value', 'host']"
          :current-page="pageIndices.request_headers"
          :per-page="rowsPerPage"
          table-variant="secondary"
          head-variant="dark"
          small
          striped
          class="mb-1"
        >
          <template v-slot:cell(name)="cellData">
            <textarea
              readonly
              rows="1"
              class="form-control-plaintext"
              wrap="soft"
              v-model="cellData.value"
            ></textarea>
          </template>
          <template v-slot:cell(value)="cellData">
            <textarea
              readonly
              rows="1"
              class="form-control-plaintext"
              wrap="soft"
              v-model="cellData.value"
            ></textarea>
          </template>
          <template v-slot:cell(host)="cellData">
            <textarea
              readonly
              rows="1"
              class="form-control-plaintext"
              :class="{
                inline: cellData.item.tracker,
                'col-11': cellData.item.tracker,
              }"
              wrap="soft"
              v-model="cellData.value"
            >
            </textarea>
            <abbr
              v-if="cellData.item.tracker"
              :title="cellData.item.tracker"
              class="align-top"
              ><b-icon icon="exclamation-circle"></b-icon
            ></abbr>
          </template>
        </b-table>
        <div class="overflow-auto">
          <b-pagination
            v-model="pageIndices.request_headers"
            :total-rows="getSessionTotalRows('request_headers')"
            first-number
            last-number
            align="fill"
            :limit="maxPagingButtons"
            :per-page="rowsPerPage"
          ></b-pagination>
        </div>
        <h4>HTTP request queries</h4>
        <b-table
          :items="sessionSummary.request_queries"
          :fields="['name', 'value', 'host']"
          :current-page="pageIndices.request_queries"
          :per-page="rowsPerPage"
          table-variant="secondary"
          head-variant="dark"
          small
          striped
          class="mb-1"
        >
          <template v-slot:cell(name)="cellData">
            <textarea
              readonly
              rows="1"
              class="form-control-plaintext"
              wrap="soft"
              v-model="cellData.value"
            ></textarea>
          </template>
          <template v-slot:cell(value)="cellData">
            <textarea
              readonly
              rows="1"
              class="form-control-plaintext"
              wrap="soft"
              v-model="cellData.value"
            ></textarea>
          </template>
          <template v-slot:cell(host)="cellData">
            <textarea
              readonly
              rows="1"
              class="form-control-plaintext"
              :class="{
                inline: cellData.item.tracker,
                'col-11': cellData.item.tracker,
              }"
              wrap="soft"
              v-model="cellData.value"
            >
            </textarea>
            <abbr
              v-if="cellData.item.tracker"
              :title="cellData.item.tracker"
              class="align-top"
              ><b-icon icon="exclamation-circle"></b-icon
            ></abbr>
          </template>
        </b-table>
        <div class="overflow-auto">
          <b-pagination
            v-model="pageIndices.request_queries"
            :total-rows="getSessionTotalRows('request_queries')"
            first-number
            last-number
            align="fill"
            :limit="maxPagingButtons"
            :per-page="rowsPerPage"
          ></b-pagination>
        </div>
        <h4>HTTP request cookies</h4>
        <b-table
          :items="sessionSummary.request_cookies"
          :fields="['name', 'value', 'host']"
          :current-page="pageIndices.request_cookies"
          :per-page="rowsPerPage"
          table-variant="secondary"
          head-variant="dark"
          small
          striped
          class="mb-1"
        >
          <template v-slot:cell(name)="cellData">
            <textarea
              readonly
              rows="1"
              class="form-control-plaintext"
              wrap="soft"
              v-model="cellData.value"
            ></textarea>
          </template>
          <template v-slot:cell(value)="cellData">
            <textarea
              readonly
              rows="1"
              class="form-control-plaintext"
              wrap="soft"
              v-model="cellData.value"
            ></textarea>
          </template>
          <template v-slot:cell(host)="cellData">
            <textarea
              readonly
              rows="1"
              class="form-control-plaintext"
              :class="{
                inline: cellData.item.tracker,
                'col-11': cellData.item.tracker,
              }"
              wrap="soft"
              v-model="cellData.value"
            >
            </textarea>
            <abbr
              v-if="cellData.item.tracker"
              :title="cellData.item.tracker"
              class="align-top"
              ><b-icon icon="exclamation-circle"></b-icon
            ></abbr>
          </template>
        </b-table>
        <div class="overflow-auto">
          <b-pagination
            v-model="pageIndices.request_cookies"
            :total-rows="getSessionTotalRows('request_cookies')"
            first-number
            last-number
            align="fill"
            :limit="maxPagingButtons"
            :per-page="rowsPerPage"
          ></b-pagination>
        </div>
        <h4>HTTP POST request JSON attributes</h4>
        <b-table
          :items="sessionSummary.postdata_json_attributes"
          :fields="['name', 'value', 'host']"
          :current-page="pageIndices.postdata_json_attributes"
          :per-page="rowsPerPage"
          table-variant="secondary"
          head-variant="dark"
          small
          striped
          class="mb-1"
        >
          <template v-slot:cell(name)="cellData">
            <textarea
              readonly
              rows="1"
              class="form-control-plaintext"
              wrap="soft"
              v-model="cellData.value"
            ></textarea>
          </template>
          <template v-slot:cell(value)="cellData">
            <textarea
              readonly
              rows="1"
              class="form-control-plaintext"
              wrap="soft"
              v-model="cellData.value"
            ></textarea>
          </template>
          <template v-slot:cell(host)="cellData">
            <textarea
              readonly
              rows="1"
              class="form-control-plaintext"
              :class="{
                inline: cellData.item.tracker,
                'col-11': cellData.item.tracker,
              }"
              wrap="soft"
              v-model="cellData.value"
            >
            </textarea>
            <abbr
              v-if="cellData.item.tracker"
              :title="cellData.item.tracker"
              class="align-top"
              ><b-icon icon="exclamation-circle"></b-icon
            ></abbr>
          </template>
        </b-table>
        <div class="overflow-auto">
          <b-pagination
            v-model="pageIndices.postdata_json_attributes"
            :total-rows="getSessionTotalRows('postdata_json_attributes')"
            first-number
            last-number
            align="fill"
            :limit="maxPagingButtons"
            :per-page="rowsPerPage"
          ></b-pagination>
        </div>
        <h4>HTTP POST request form fields</h4>
        <b-table
          :items="sessionSummary.postdata_form_params"
          :fields="['name', 'value', 'host']"
          :current-page="pageIndices.postdata_form_params"
          :per-page="rowsPerPage"
          table-variant="secondary"
          head-variant="dark"
          small
          striped
          class="mb-1"
        >
          <template v-slot:cell(name)="cellData">
            <textarea
              readonly
              rows="1"
              class="form-control-plaintext"
              wrap="soft"
              v-model="cellData.value"
            ></textarea>
          </template>
          <template v-slot:cell(value)="cellData">
            <textarea
              readonly
              rows="1"
              class="form-control-plaintext"
              wrap="soft"
              v-model="cellData.value"
            ></textarea>
          </template>
          <template v-slot:cell(host)="cellData">
            <textarea
              readonly
              rows="1"
              class="form-control-plaintext"
              :class="{
                inline: cellData.item.tracker,
                'col-11': cellData.item.tracker,
              }"
              wrap="soft"
              v-model="cellData.value"
            >
            </textarea>
            <abbr
              v-if="cellData.item.tracker"
              :title="cellData.item.tracker"
              class="align-top"
              ><b-icon icon="exclamation-circle"></b-icon
            ></abbr>
          </template>
        </b-table>
        <div class="overflow-auto">
          <b-pagination
            v-model="pageIndices.postdata_form_params"
            :total-rows="getSessionTotalRows('postdata_form_params')"
            first-number
            last-number
            align="fill"
            :limit="maxPagingButtons"
            :per-page="rowsPerPage"
          ></b-pagination>
        </div>
      </div>
    </div>
  </b-container>
</template>

<script>
import axios from "axios";
import uiResources from "../resources/default";
import componentHeader from "../components/ComponentHeader";

export default {
  components: { componentHeader },
  data: function () {
    return {
      sessionId: null,
      sessionSummary: {},
      pageIndices: {
        request_headers: 1,
        request_queries: 1,
        request_cookies: 1,
        postdata_json_attributes: 1,
        postdata_form_params: 1,
      },
      rowsPerPage: 5,
      maxPagingButtons: 10,
      loaded: false,
      loading: false,
    };
  },
  methods: {
    getSessionSummary: function () {
      this.loading = true;
      axios.get(`/session/${this.sessionId}/summary`).then((result) => {
        this.loading = false;
        if (result.data.returned) {
          this.sessionSummary = result.data.returned;
          this.loaded = true;
        }
      });
    },
    getSessionName: function () {
      if (this.sessionSummary.name) return `"${this.sessionSummary.name}"`;
      return "";
    },
    getSessionTotalRows: function (summaryTableName) {
      if (this.sessionSummary[summaryTableName])
        if (Array.isArray(this.sessionSummary[summaryTableName]))
          return this.sessionSummary[summaryTableName].length;
      return 0;
    },
    humaniseText: function (text) {
      if (text) return uiResources.humaniseText(text);
      else return "";
    },
    triggerBrowserToDownloadCSV: function (csvContent, filename) {
      var downloadLink = document.createElement("a");
      let fileBlob = new Blob([csvContent], {type: "text/csv;charset=utf-8;"});
      /*downloadLink.href = encodeURI(
        "data:text/csv;charset=utf-8," + csvContent
      );*/
      downloadLink.href = window.URL.createObjectURL(fileBlob);
      downloadLink.target = "_blank";
      downloadLink.download = filename;
      downloadLink.click();
    },
    formatCSVValue: function (value) {
      if (value) {
        value = value.toString();
        value = value.replace(/[\x00-\x09\x0B-\x0C\x0E-\x1F\x7F-\x9F]/g, ''); // remove non-printable characters
        return `"${value.replace(/"/g, '""')}"`;
      } else return '""';
    },
    createCSVLine: function (dict, keys) {
      return keys.map((k) => this.formatCSVValue(dict[k])).join(",");
    },
    exportHostCount: function () {
      if (this.sessionSummary.hosts) {
        let csvContent = this.sessionSummary.hosts
          .map((hostEntry) =>
            this.createCSVLine(hostEntry, ["host", "count", "tracker"])
          )
          .join("\n");
        csvContent =
          ["host", "count", "tracker"]
            .map((header) => `"${header}"`)
            .join(",") +
          "\n" +
          csvContent;
        let sessionName = this.sessionSummary.name
          ? `${this.sessionSummary.name}_`
          : "";
        this.triggerBrowserToDownloadCSV(
          csvContent,
          `${this.sessionId}_${sessionName}hostname_counts.csv`
        );
      }
    },
    exportDataValues: function () {
      let request_parts = [
        "request_headers",
        "request_queries",
        "request_cookies",
        "postdata_form_params",
        "postdata_json_attributes",
      ];

      let csvContent = request_parts
        .map((part) =>
          this.sessionSummary[part]
            .map(
              (entry) =>
              `"${part}",` + 
                this.createCSVLine(entry, [
                  "name",
                  "value",
                  "host",
                  "tracker",
                ])
            )
            .join("\n")
        )
        .join("\n");

      csvContent =
        ["http_part", "name", "value", "host", "tracker"]
          .map((header) => `"${header}"`)
          .join(",") +
        "\n" +
        csvContent;
      let sessionName = this.sessionSummary.name
        ? `${this.sessionSummary.name}_`
        : "";
      this.triggerBrowserToDownloadCSV(
        csvContent,
        `${this.sessionId}_${sessionName}data_values.csv`
      );
    },
  },
  computed: {
    getSessionStartTime: function () {
      if (this.sessionSummary.created) {
        return uiResources.getDateText(new Date(this.sessionSummary.created));
      }
      return "";
    },
    getSessionEndTime: function () {
      if (this.sessionSummary.ended) {
        return uiResources.getDateText(new Date(this.sessionSummary.ended));
      }
      return "";
    },
  },
  mounted: function () {
    if (!this.$parent.isLoggedIn) {
      //this.$router.push({ name: "Login", query: { destination: "Sessions" } });
      return;
    }
    if (this.$route.query.id) {
      this.sessionId = this.$route.query.id;
    } else if (this.$route.params.sessionId) {
      this.sessionId = this.$route.params.sessionId;
    }
    if (this.sessionId) {
      this.getSessionSummary();
    }
  },
};
</script>

<style scoped>
.spinner {
  width: 3rem;
  height: 3rem;
}

.inline {
  display: inline;
}

.tracker-sign {
  display: inline;
  padding-left: 0;
  padding-right: 0;
}
</style>
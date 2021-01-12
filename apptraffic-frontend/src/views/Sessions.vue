<template>
  <b-container>
    <componentHeader title="Sessions" />
    <b-row class="row justify-content-end">
      <div class="col-2 col-sm-2 col-md-1 mb-3">
        <b-button variant="secondary" @click="getSessions">
          <b-icon icon="arrow-repeat" aria-hidden="true"></b-icon>
        </b-button>
      </div>
      <div class="col-4 col-sm-4 col-md-2 mb-3">
        <b-button block variant="danger" to="record">
          <b-icon icon="camera-video" aria-hidden="true"></b-icon>&nbsp;New
        </b-button>
      </div>
    </b-row>
    <b-table
      :items="sessionTableRows"
      :fields="sessionTableColumns"
      responsive="sm"
      :current-page="currentPageIndex"
      :per-page="rowsPerPage"
    >
      <!--
      <template v-slot:cell(time)="cellData">{{ cellData.value }}</template>
      <template v-slot:cell(duration)="cellData">{{ cellData.value }}</template>
      <template v-slot:cell(mode)="cellData">{{ cellData.value }}</template>
      <template v-slot:cell(status)="cellData">{{ cellData.value }}</template>
      <template v-slot:cell(sessionName)="cellData">{{
        cellData.value
      }}</template>
      <template v-slot:cell(exitNodeName)="cellData">{{
        cellData.value
      }}</template>
      -->
      <template v-slot:cell(sessionId)="cellData">
        <!--
        <b-button
           @click="openSession(cellData.value)"
           v-show="getSessionStatus(cellData.value) === 'recording'"
          size="sm"
          variant="info"
          class="mr-1 mb-1"
        >
          <b-icon icon="clock" aria-hidden="true"></b-icon>
        </b-button>-->
        <router-link :to="{ name: 'Record', query: { id: cellData.value } }">
          <b-button
            v-show="getSessionStatus(cellData.value) === 'recording'"
            size="sm"
            variant="info"
            class="mr-1 mb-1"
          >
            <b-icon icon="clock" aria-hidden="true"></b-icon>
          </b-button>
        </router-link>
        <b-button
          @click="stopSession(cellData.value)"
          v-show="getSessionStatus(cellData.value) === 'recording'"
          size="sm"
          variant="danger"
          class="mr-1 mb-1"
        >
          <b-icon icon="camera-video-off" aria-hidden="true"></b-icon>
        </b-button>
        <!--
        <b-button
          :href="'/about/' + cellData.value"
          v-show="['recording','ended'].includes(getSessionStatus(cellData.value))"
          size="sm"
          variant="success"
          class="mr-1 mb-1"
        >
          <b-icon icon="play-fill" aria-hidden="true"></b-icon>
        </b-button>-->
        <!--
        <b-button
           @click="openSessionSummary(cellData.value)"
           v-show="['ending', 'ended'].includes(getSessionStatus(cellData.value)) && getSessionMode(cellData.value) === 'decrypted'"
          size="sm"
          variant="primary"
          class="mr-1 mb-1"
        >
          <b-icon icon="bar-chart-line" aria-hidden="true"></b-icon>
        </b-button>-->
        <router-link :to="{ name: 'Summary', query: { id: cellData.value } }">
          <b-button
            v-show="
              ['ending', 'ended'].includes(getSessionStatus(cellData.value)) &&
              getSessionMode(cellData.value) === 'decrypted'
            "
            size="sm"
            variant="primary"
            class="mr-1 mb-1"
          >
            <b-icon icon="bar-chart-line" aria-hidden="true"></b-icon>
          </b-button>
        </router-link>
        <b-button
          @click="downloadSessionData(cellData.value)"
          v-show="
            ['ending', 'ended'].includes(getSessionStatus(cellData.value))
          "
          size="sm"
          variant="primary"
          class="mr-1 mb-1"
        >
          <b-icon icon="download" aria-hidden="true"></b-icon>
        </b-button>
        <b-button
          @click="removeSession(cellData.value)"
          v-show="
            ![
              'creating',
              'recording',
              'creating_entry_hub',
              'creating_exit_hub',
              'created_entry_hub',
            ].includes(getSessionStatus(cellData.value))
          "
          size="sm"
          variant="secondary"
          class="mr-1 mb-1"
        >
          <b-icon icon="trash" aria-hidden="true"></b-icon>
        </b-button>
      </template>
    </b-table>
    <div class="overflow-auto">
      <b-pagination
        v-model="currentPageIndex"
        :total-rows="sessionTableRows.length"
        first-number
        last-number
        align="center"
        :limit="maxPagingButtons"
        :per-page="rowsPerPage"
      ></b-pagination>
    </div>
  </b-container>
</template>

<script>
import axios from "axios";
import uiResources from "../resources/default";
import componentHeader from "../components/ComponentHeader";

export default {
  data: function () {
    return {
      recordedSessions: [],
      sessionTableRows: [],
      currentPageIndex: 1,
      rowsPerPage: 10,
      maxPagingButtons: 10,
    };
  },
  methods: {
    getSessions: function () {
      axios.get(`/sessions`).then((result) => {
        if (result.data.returned) this.recordedSessions = result.data.returned;
        this.updateSessionTableRows();
      });
    },
    updateSessionTableRows: function () {
      this.sessionTableRows = this.recordedSessions.map(function (session) {
        var startDate = new Date(session.created);
        var endDate = null;
        if (Object.keys(session).includes("ended"))
          endDate = new Date(session.ended);
        let sessoinTableRow = {
          time: uiResources.getDateText(startDate),
          mode: uiResources.humaniseText(session.intercept_mode),
          duration: !endDate
            ? "N/A"
            : uiResources.timeDifferenceText(startDate, endDate),
          //exitNodeName: session.resources.exit_node.location,
          sessionName: session.name ? session.name : "",
          username: session.username ? session.username : "",
          sessionId: session._id,
          status: uiResources.humaniseText(
            uiResources.recordingStatuses[session.status]
          ),
        };
        return sessoinTableRow;
      });
    },
    stopSession: function (sessionId, promptConfirmBox = true) {
      if (promptConfirmBox) {
        if (!confirm("Are you sure you want to stop this session?")) return;
      }
      axios.post(`/session/${sessionId}/stop`).then((result) => {
        if (result.data.returned) {
          this.getSessions();
        }
      });
    },
    removeSession: function (sessionId, promptConfirmBox = true) {
      if (promptConfirmBox) {
        if (!confirm("Are you sure you want to delete this session?")) return;
      }
      axios.delete(`/session/${sessionId}/remove`).then((result) => {
        if (result.data.returned) {
          this.getSessions();
        }
      });
    },
    /*
    openSession: function(sessionId) {
       this.$router.push({ name: "Record", query: { id: sessionId } });
    },*/
    getSessionStatus: function (sessionId) {
      for (let i = 0; i < this.recordedSessions.length; i++) {
        if (this.recordedSessions[i]._id === sessionId)
          return this.recordedSessions[i].status;
      }
      return null;
    },
    getSessionMode: function (sessionId) {
      for (let i = 0; i < this.recordedSessions.length; i++) {
        if (this.recordedSessions[i]._id === sessionId)
          return this.recordedSessions[i].intercept_mode;
      }
      return null;
    },
    downloadSessionData: function (sessionId) {
      axios.get(`/session/${sessionId}/download`).then((result) => {
        if (result.data.returned) {
          var downloadLink = document.createElement("a");
          downloadLink.href =
            axios.defaults.baseURL + `/download/${result.data.returned}`;
          downloadLink.target = "_blank";
          downloadLink.click();
        } else {
          alert(
            "The data file will be available for download after the trasnfer process completes.  Please try again later."
          );
        }
      });
    },
    /*
    openSessionSummary: function(sessionId) {
      this.$router.push({ name: "Summary", query: { id: sessionId } });
    }*/
  },
  computed: {
    sessionTableColumns: function() {
      let columns = [
        { key: "time", label: "Time" },
        { key: "duration", label: "Duration" },
        { key: "mode", label: "Mode" },
        { key: "status", label: "Status" },
        { key: "sessionName", label: "Name" },
        { key: "sessionId", label: "Actions" },
      ];
      if (this.$parent.userPrivileges.includes("admin"))
        columns.splice(4,0, {key: "username", label: "User"});
      return columns;
    }
  },
  mounted: function () {
    if (this.$parent.isLoggedIn) {
      this.getSessions();
    }
    /*
    if (!this.$parent.isLoggedIn) {
      this.$router.push({ name: "Login", query: { destination: "Sessions" } });
      return;
    }
    this.getSessions();*/
    /*
    this.recordedSessions = [
      {
        time: "09:11, 01 April 2020",
        duration: "10:20",
        exitNodeName: "Lowlands University, United Kingdom",
        sessionId: "bilibala",
        status: "Ended",
      },
      {
        time: "21:31, 31 August 2019",
        duration: "03:00",
        exitNodeName: "University of Redwood, United States",
        sessionId: "popobeating",
        status: "Ended",
      },
    ];*/
  },
  components: { componentHeader },
};
</script>

<style scoped>
</style>
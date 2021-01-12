<template>
  <div id="app">
    <b-navbar toggleable="lg" type="light">
      <b-navbar-brand href="#">
        <b-img
          src="./assets/apptraffic_logo.png"
          alt="AppTraffic"
          class="navbar-logo"
        />
        <!--
        <b-img src="./assets/vue-logo.png" fluid alt="AppTraffic"></b-img>
        -->
      </b-navbar-brand>
      <b-navbar-toggle target="nav-collapse"></b-navbar-toggle>
      <b-collapse id="nav-collapse" is-nav>
        <b-navbar-nav>
          <b-nav-item to="./">
            <b-icon-info></b-icon-info>&nbsp;Home
          </b-nav-item>
          <b-nav-item to="record">
            <b-icon-camera-video></b-icon-camera-video>&nbsp;Record
          </b-nav-item>
          <b-nav-item to="sessions">
            <b-icon-play></b-icon-play>&nbsp;Sessions
          </b-nav-item>
        </b-navbar-nav>
        <b-navbar-nav class="ml-auto">
          <b-nav-item to="login" :hidden="isLoggedIn">
            <b-icon-person></b-icon-person>&nbsp;Login
          </b-nav-item>
          <b-nav-item
            @click="loginChanged({ loggedIn: false })"
            :hidden="!isLoggedIn"
          >
            <b-icon-door-closed></b-icon-door-closed>&nbsp;Logout as
            {{ username }}
          </b-nav-item>
          <b-nav-item to="signup" :hidden="isLoggedIn">
            <b-icon-pencil-square></b-icon-pencil-square>&nbsp;Sign up
          </b-nav-item>
        </b-navbar-nav>
      </b-collapse>
    </b-navbar>
    <hr class="mb-4 mt-1" />
    <!--
    <div id="nav">
      <router-link to="/">Home</router-link> |
      <router-link to="/about">About</router-link>
    </div>-->
    <router-view
      @onLoginChanged="loginChanged"
      class="main-component"
      :key="isLoggedIn"
    />
    <hr class="mt-4" />
    <footer class="container footer-container mt-auto">
      <div class="row mt-3 pt-3">
        <div class="col-12 col-sm-6 text-center">
          <a href="https://www.mediacoop.uni-siegen.de/" target="_blank">
            <img
              src="https://www.mediacoop.uni-siegen.de/wp-content/themes/mdk/img/mdk_logo.png"
              alt="SFB 1187 - MEDIEN DER KOOPERATION"
              class="image-fluid footer-logo sfb-footer-logo"
            />
          </a>
        </div>
        <div class="col-12 col-sm-6 text-center">
          <a href="https://www.uni-siegen.de/" target="_blank">
            <img
              src="https://www.mediacoop.uni-siegen.de/wp-content/themes/mdk/img/uni-siegen_logo.png"
              alt="Universität Siegen"
              class="image-fluid footer-logo siegen-footer-logo"
            />
          </a>
        </div>
      </div>
    </footer>
  </div>
</template>

<script>
import axios from "axios";

export default {
  data: function () {
    return {
      isLoggedIn: false,
      username: null,
      jwtToken: null,
      userPrivileges: [],
    };
  },
  methods: {
    loginChanged: function (loginStatus) {
      // console.log("login status changed");
      if (loginStatus.loggedIn) {
        this.username = loginStatus.username;
        this.jwtToken = loginStatus.jwtToken;
        axios.defaults.headers.common["Authorization"] =
          "Bearer " + this.jwtToken;
        this.isLoggedIn = true;
        localStorage.setItem(
          "AppTrafficUserSession",
          JSON.stringify({ username: this.username, jwtToken: this.jwtToken })
        );
        axios.get("/user/privileges").then((result) => {
          if (result.data.returned) {
            this.userPrivileges = result.data.returned;
            if (this.userPrivileges.length <= 0)
              this.loginChanged({ loggedIn: false });
          } else {
            this.loginChanged({ loggedIn: false });
          }
        });
        // console.log("Hello " + this.username);
      } else {
        localStorage.clear();
        this.isLoggedIn = false;
        this.username = null;
        this.jwtToken = null;
        delete axios.defaults.headers.common["Authorization"];
        this.$router.push({ name: "Home" });
      }
    },
  },
  mounted: function () {
    if (localStorage.getItem("AppTrafficUserSession") != null) {
      let userSession = JSON.parse(
        localStorage.getItem("AppTrafficUserSession")
      );
      //axios.defaults.headers.common["Authorization"] =
      //  "Bearer " + userSession.jwtToken;
      //axios.get("/user/is_session_valid").then((result) => {
      this.loginChanged({
        loggedIn: true, // a check will be performed
        username: userSession.username,
        jwtToken: userSession.jwtToken,
      });
      //});
    }
  },
};
</script>

<style lang="scss">
.main-component {
  font-size: 1.1em;
}

.navbar-logo {
  height: 2.5em;
}

.sfb-footer-logo {
  height: 2.5em;
}

.siegen-footer-logo {
  height: 2em;
}

.footer-container {
  margin-top: 2em;
}

/*
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
}

#nav {
  padding: 30px;

  a {
    font-weight: bold;
    color: #2c3e50;

    &.router-link-exact-active {
      color: #42b983;
    }
  }
}*/
</style>

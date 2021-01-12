<template>
  <b-container>
    <componentHeader title="Login" />
    <b-row>
      <b-container>
        <b-form @submit="onSubmit">
          <b-form-row class="login-form-row">
            <label for="username-input" class="col-sm-3 col-form-label">Username or Email</label>
            <div class="col-sm-9">
              <b-form-input
                type="text"
                id="username-input"
                :readonly="loginRequestInProgress"
                v-model="loginForm.usernameOrEmail"
              />
            </div>
          </b-form-row>
          <b-form-row class="login-form-row">
            <label for="password-input" class="col-sm-3 col-form-label">Password</label>
            <div class="col-sm-9">
              <b-form-input
                type="password"
                id="password-input"
                :readonly="loginRequestInProgress"
                v-model="loginForm.password"
              />
            </div>
          </b-form-row>
          <b-form-row class="login-form-row">
            <b-container>
              <b-alert v-model="showErrorAlert" variant="danger" dismissible>{{ errorMessage }}</b-alert>
            </b-container>
          </b-form-row>
          <b-row class="login-form-row">
            <b-container class="text-center">
              <b-button
                class="btn-lg col-12 col-sm-6 col-md-3"
                type="submit"
                :disabled="loginRequestInProgress"
                variant="primary"
              >
                <b-spinner small v-show="loginRequestInProgress"></b-spinner>&nbsp; Login
              </b-button>
              <p class="small mt-3">
                <router-link to="signup">Sign up</router-link>&nbsp;if you do not have an account
              </p>
            </b-container>
          </b-row>
        </b-form>
      </b-container>
    </b-row>
  </b-container>
</template>

<script>
import componentHeader from "../components/ComponentHeader";
import axios from "axios";
import uiResources from "../resources/default";

export default {
  data: function () {
    return {
      loginForm: {
        usernameOrEmail: null,
        password: null,
      },
      showErrorAlert: false,
      errorMessage: "",
      loginRequestInProgress: false,
    };
  },
  methods: {
    onSubmit: function (event) {
      event.preventDefault();
      this.loginRequestInProgress = true;
      axios
        .post("/user/login", this.loginForm)
        .then((result) => {
          if (result.data.returned) {
            if (result.data.returned.authenticated === true) {
              this.$emit("onLoginChanged", {
                loggedIn: result.data.returned.authenticated,
                username: result.data.returned.username,
                jwtToken: result.data.returned.jwtToken,
              });
              if (this.$route.query.destination)
                this.$router.push({ name: this.$route.query.destination });
              else this.$router.push({ name: "Record" });
            } else {
              this.errorMessage = uiResources.errorMessages.loginFailure;
              this.showErrorAlert = true;
            }
          } else {
            this.errorMessage = uiResources.errorMessages.pleaseContactAdmin;
            this.showErrorAlert = true;
          }
        })
        .catch((axiosError) => {
          console.log(axiosError);
          this.errorMessage = uiResources.errorMessages.serviceUnavailable;
          this.showErrorAlert = true;
        })
        .finally(() => {
          this.loginRequestInProgress = false;
        });
    },
  },
  components: { componentHeader },
};
</script>

<style scoped>
.login-form-row {
  margin-top: 0.7em;
}
</style>
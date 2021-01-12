<template>
  <b-container>
    <componentHeader title="Sign up" />
    <b-row>
      <b-container v-show="!signupDone">
        <b-form @submit="onSubmit">
          <b-form-row class="signup-form-row">
            <label for="username-input" class="col-sm-3 col-form-label">Username</label>
            <div class="col-sm-9">
              <b-form-input
                type="text"
                id="username-input"
                :readonly="signupFormRequestInProgress"
                v-model="signupForm.username"
              />
            </div>
          </b-form-row>
          <b-form-row class="signup-form-row">
            <label for="email-input" class="col-sm-3 col-form-label">Email</label>
            <div class="col-sm-9">
              <b-form-input
                type="text"
                id="email-input"
                :readonly="signupFormRequestInProgress"
                v-model="signupForm.email"
              />
            </div>
          </b-form-row>
          <b-form-row class="signup-form-row">
            <label for="password-input" class="col-sm-3 col-form-label">Password</label>
            <div class="col-sm-9">
              <b-form-input
                type="password"
                id="password-input"
                :readonly="signupFormRequestInProgress"
                v-model="signupForm.password"
              />
            </div>
          </b-form-row>
          <b-form-row class="signup-form-row">
            <label for="confirm-password-input" class="col-sm-3 col-form-label">Confirm password</label>
            <div class="col-sm-9">
              <b-form-input
                type="password"
                id="confirm-password-input"
                :readonly="signupFormRequestInProgress"
                v-model="signupForm.confirmPassword"
              />
            </div>
          </b-form-row>
          <b-form-row class="signup-form-row">
            <b-container>
              <b-alert v-model="showErrorAlert" variant="danger" dismissible>{{ errorMessage }}</b-alert>
            </b-container>
          </b-form-row>
          <b-row class="signup-form-row">
            <b-container class="text-center">
              <b-button
                class="btn-lg col-12 col-sm-6 col-md-3"
                type="submit"
                :disabled="signupFormRequestInProgress"
                variant="primary"
              >
                <b-spinner small v-show="signupFormRequestInProgress"></b-spinner>&nbsp; Sign up
              </b-button>
            </b-container>
          </b-row>
        </b-form>
      </b-container>
      <b-container v-show="signupDone">
        <b-card class="text-center">
          <b-card-text>Thank you for signing up. The administrator is reviewing your profile. You will receive an email with further instructions.</b-card-text>
        </b-card>
      </b-container>
    </b-row>
  </b-container>
</template>

<script>
import axios from "axios";
import uiResources from "../resources/default";
import componentHeader from "../components/ComponentHeader";

export default {
  data: function () {
    return {
      signupForm: {
        email: null,
        username: null,
        password: null,
        confirmPassword: null,
      },
      showErrorAlert: false,
      errorMessage: "",
      signupFormRequestInProgress: false,
      signupDone: false,
    };
  },
  methods: {
    onSubmit: function (event) {
      event.preventDefault();
      //console.log(JSON.stringify(this.signupForm));
      this.signupFormRequestInProgress = true;
      axios
        .post("/user/signup", this.signupForm)
        .then((result) => {
          if (result.data.returned === true) {
            this.signupDone = true;
          } else if (result.data.errorMessage) {
            this.errorMessage = result.data.errorMessage;
            this.showErrorAlert = true;
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
          this.signupFormRequestInProgress = false;
        });
    },
    onSubmitError: function (errorMessage) {
      this.errorMessage = errorMessage;
      this.showErrorAlert = true;
    },
  },
  components: { componentHeader },
};
</script>

<style scoped>
.signup-form-row {
  margin-top: 0.7em;
}
</style>
<template>
  <b-container id="record-container" ref="recordContainer">
    <componentHeader :title="'Record ' + selectedRecordModeText" />
    <b-row class="row" v-show="step === 1">
      <div
        class="col-12 col-sm-6 col-lg-4"
        :class="{ 'text-muted': !recordOptionEnabled('metadata') }"
      >
        <div class="card box-shadow mb-2">
          <div class="card-header text-center">
            <h4>Metadata</h4>
          </div>
          <div class="card-body">
            <div class="record-mode-description">
              <p>Key features of the packets in transit without the content</p>
              <ul>
                <li>Time</li>
                <li>Destination IP address</li>
                <li>Hostname</li>
                <li>Size</li>
              </ul>
            </div>
            <button
              type="button"
              class="btn btn-lg btn-block btn-secondary"
              @click="nextStep('metadata')"
              :disabled="!recordOptionEnabled('metadata')"
            >
              Go
            </button>
          </div>
        </div>
      </div>
      <div
        class="col-12 col-sm-6 col-lg-4"
        :class="{ 'text-muted': !recordOptionEnabled('decrypted') }"
      >
        <div class="card box-shadow mb-2">
          <div class="card-header text-center">
            <h4>Decrypted</h4>
          </div>
          <div class="card-body">
            <div class="record-mode-description">
              <p>Metadata + the content in decrypted https traffic</p>
              <ul>
                <li>URL</li>
                <li>Header</li>
                <li>Response</li>
              </ul>
              <div class="text-muted mt-4 record-mode-note">
                <small>
                  Note: The use of an iOS device is recommended in the Decrypted
                  Mode. Devices running Android version ≥ 7.0 do not work with
                  this mode,
                  <a
                    href="https://android-developers.googleblog.com/2016/07/changes-to-trusted-certificate.html"
                    target="_blank"
                    >see why</a
                  >.
                </small>
              </div>
            </div>
            <button
              type="button"
              class="btn btn-lg btn-block btn-secondary"
              @click="nextStep('decrypted')"
              :disabled="!recordOptionEnabled('decrypted')"
            >
              Go
            </button>
          </div>
        </div>
      </div>
      <div
        class="col-12 col-sm-6 col-lg-4"
        :class="{ 'text-muted': !recordOptionEnabled('raw') }"
      >
        <div class="card box-shadow mb-2">
          <div class="card-header text-center">
            <h4>Raw</h4>
          </div>
          <div class="card-body">
            <div class="record-mode-description">
              <p>Metadata + raw (undecrypted) content</p>
            </div>
            <button
              type="button"
              class="btn btn-lg btn-block btn-secondary"
              @click="nextStep('raw')"
              :disabled="!recordOptionEnabled('raw')"
            >
              Go
            </button>
          </div>
        </div>
      </div>
    </b-row>

    <b-row class="row" v-show="step === 2">
      <div class="col-12 col-md-11">
        <div class="card box-shadow mb-2">
          <div class="card-header text-center">
            <h4>Choose the name and the locations</h4>
          </div>
          <div class="card-body">
            <div class="record-device-traffic-description text-center">
              <div class="row justify-content-center">
                <div class="col-12 col-md-3 text-left">Session Name</div>
                <div class="form-group col-12 col-md-7 text-left">
                  <b-form-input
                    type="text"
                    v-model="sessionName"
                    placeholder="For example, the name of the app to be studied"
                  />
                  <small>Please give the session a name (optional)</small>
                </div>
              </div>
            </div>
            <div class="record-device-traffic-description text-center">
              <div class="row justify-content-center">
                <div class="col-12 col-md-3 text-left">Traffic Exit Point</div>
                <div class="form-group col-12 col-md-7 text-left">
                  <b-form-select
                    v-model="selectedExitNode"
                    :options="exitNodeOptionList"
                  ></b-form-select>
                  <small
                    >Please choose where the traffic will exit for the
                    Internet</small
                  >
                </div>
              </div>
            </div>
            <div class="record-device-traffic-description text-center mt-2">
              <div class="row justify-content-center">
                <div class="col-12 col-md-3 text-left">Traffic Entry Point</div>
                <div class="form-group col-12 col-md-7 text-left">
                  <b-form-select
                    v-model="selectedEntryNode"
                    :options="entryNodeOptionList"
                  ></b-form-select>
                  <small
                    >Please choose where your device be connecting to through a
                    VPN connection. The best option is the location nearest to
                    your device.</small
                  >
                </div>
              </div>
            </div>
            <div class="row justify-content-center mt-3">
              <div class="col-5">
                <button
                  type="button"
                  class="btn btn-block btn-lg btn-outline-secondary"
                  @click="previousStep"
                >
                  Back
                </button>
              </div>
              <div class="col-5">
                <button
                  type="button"
                  class="btn btn-block btn-lg btn-secondary"
                  @click="nextStep"
                  :disabled="!selectedExitNode"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </b-row>

    <b-row class="row justify-content-md-center" v-show="step === 3">
      <div class="col-12 col-md-11">
        <div class="card box-shadow mb-2">
          <div class="card-header text-center">
            <h4>Configure your device</h4>
          </div>
          <div class="card-body text-center">
            <div class="record-device-traffic-description">
              <p class="mb-1">
                We need to configure a VPN connection on your device for
                AppTraffic to work
              </p>
              <p>Please select the operating system of your device</p>
              <div class="row justify-content-center mt-3">
                <div class="col-8 col-xs-5 col-md-3 mb-1">
                  <button
                    class="system-selection-button border border-secondary rounded"
                    @click="nextStep('android')"
                  >
                    <b-img
                      src="../assets/android_device.png"
                      class="system-selection-icon"
                      fluid
                      alt="Android device"
                    />
                    <p>Android</p>
                  </button>
                </div>
                <div class="col-8 col-xs-5 col-md-3 mb-1">
                  <button
                    class="system-selection-button border border-secondary rounded"
                    @click="nextStep('ios')"
                  >
                    <b-img
                      src="../assets/ios_device.png"
                      class="system-selection-icon"
                      fluid
                      alt="Apple iOS device"
                    />
                    <p>iOS</p>
                  </button>
                </div>
                <div class="col-8 col-xs-5 col-md-3 mb-1">
                  <button
                    class="system-selection-button border border-secondary rounded"
                    @click="nextStep('other')"
                  >
                    <b-img
                      src="../assets/other_devices.png"
                      class="system-selection-icon"
                      fluid
                      alt="Other devices"
                    />
                    <p>Other</p>
                  </button>
                </div>
              </div>
            </div>
            <div class="row justify-content-center mt-4">
              <div class="col-12 col-lg-3 mt-1">
                <button
                  type="button"
                  class="btn btn-block btn-lg btn-outline-secondary"
                  @click="previousStep"
                >
                  Back
                </button>
              </div>
              <div class="col-12 col-lg-9 mt-1">
                <button
                  type="button"
                  @click="nextStep('skip')"
                  class="btn btn-block btn-lg btn-secondary"
                >
                  Skip
                  <small
                    >&#9758; my device has been configured for AppTraffic
                    before</small
                  >
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </b-row>

    <b-row class="row" v-show="step === 4">
      <div class="col-12 col-md-11">
        <div class="card box-shadow mb-2">
          <div class="card-header text-center">
            <h4>Configure your device</h4>
          </div>
          <div class="card-body text-center">
            <div class="record-device-traffic-description">
              <div class="row">
                <div class="offset-1 col-10">
                  <div v-show="selectedDevice === 'other'" class="text-left">
                    The way to setup a VPN configuration varies from system to
                    system. Please consult the manual published by your device
                    manufacture. You will need the following information when
                    you add the configuration.
                    <b-alert
                      show
                      variant="info"
                      v-if="userVPNInfo"
                      class="mt-3"
                    >
                      <b-row v-if="userVPNInfo.name">
                        <div class="col-12 col-lg-4 text-lg-right">
                          Connection name
                        </div>
                        <div class="col-12 col-lg-8">
                          <strong>{{ userVPNInfo.name }}</strong>
                        </div>
                      </b-row>
                      <b-row class="mt-1">
                        <div class="col-12 col-lg-4 text-lg-right">
                          VPN type
                        </div>
                        <div class="col-12 col-lg-8">
                          <strong>L2TP over IPSec</strong>
                        </div>
                      </b-row>
                      <b-row class="mt-1">
                        <div class="col-12 col-lg-4 text-lg-right">
                          Machine authentication
                        </div>
                        <div class="col-12 col-lg-8">
                          <strong>Preshared key (PSK) / Shared secret</strong>
                        </div>
                      </b-row>
                      <b-row
                        class="mt-1"
                        v-if="userVPNInfo.pre_shared_key_ascii"
                      >
                        <div class="col-12 col-lg-4 text-lg-right">
                          Preshared key / secret
                        </div>
                        <div class="col-12 col-lg-8">
                          <strong>{{
                            userVPNInfo.pre_shared_key_ascii
                          }}</strong>
                        </div>
                      </b-row>
                      <b-row class="mt-1" v-if="userVPNInfo.hostname">
                        <div class="col-12 col-lg-4 text-lg-right">
                          Server address
                        </div>
                        <div class="col-12 col-lg-8">
                          <strong>{{ userVPNInfo.hostname }}</strong>
                        </div>
                      </b-row>
                      <b-row class="mt-1">
                        <div class="col-12 col-lg-4 text-lg-right">
                          User authentication
                        </div>
                        <div class="col-12 col-lg-8">
                          <strong>Username and password</strong>
                        </div>
                      </b-row>
                      <b-row class="mt-1" v-if="userVPNInfo.username">
                        <div class="col-12 col-lg-4 text-lg-right">
                          Username
                        </div>
                        <div class="col-12 col-lg-8">
                          <strong>{{ userVPNInfo.username }}</strong>
                        </div>
                      </b-row>
                      <b-row class="mt-1" v-if="userVPNInfo.password">
                        <div class="col-12 col-lg-4 text-lg-right">
                          Password
                        </div>
                        <div class="col-12 col-lg-8">
                          <strong>{{ userVPNInfo.password }}</strong>
                        </div>
                      </b-row>
                    </b-alert>
                    <p>
                      To use the Decrypted Mode,
                      <a
                        href="#"
                        target="_blank"
                        @click.prevent="downloadUserCertificate"
                        >click here</a
                      >
                      to download your certificate and add it to the list of
                      Certificate Authorities (CA) trusted by your system.
                    </p>
                  </div>
                  <div v-show="selectedDevice === 'android'" class="text-left">
                    <p class="record-mode-note">
                      <small>
                        Some may find the following instructions not
                        corresponding to their Android user interface due to
                        customisation by the device manufactures. In case of
                        doubt, please refer to
                        <a
                          href="https://support.google.com/android/answer/9089766"
                          target="_blank"
                          >Google's documentation on configuring a VPN
                          connection on Android</a
                        >
                        or the manuals published by the device manufactures.
                      </small>
                    </p>
                    <p>
                      1. On your Android device, open
                      <strong>&#x2699; Settings</strong>.
                    </p>
                    <p>
                      2. Tap
                      <strong
                        >Network &#38; internet &#x2B9E; Advanced &#x2B9E;
                        VPN</strong
                      >
                    </p>
                    <p>
                      3. Tap
                      <strong>&#x2795;</strong> at the top right
                    </p>
                    <p>4. Enter the following information</p>
                    <b-alert show variant="info" v-if="userVPNInfo">
                      <b-row v-if="userVPNInfo.name">
                        <div class="col-12 col-lg-4 text-lg-right">Name</div>
                        <div class="col-12 col-lg-8">
                          <strong>{{ userVPNInfo.name }}</strong>
                        </div>
                      </b-row>
                      <b-row class="mt-1">
                        <div class="col-12 col-lg-4 text-lg-right">Type</div>
                        <div class="col-12 col-lg-8">
                          <strong>L2TP/IPSec PSK</strong>
                        </div>
                      </b-row>
                      <b-row
                        class="mt-1"
                        v-if="userVPNInfo.pre_shared_key_ascii"
                      >
                        <div class="col-12 col-lg-4 text-lg-right">
                          IPSec preshared key
                        </div>
                        <div class="col-12 col-lg-8">
                          <strong>{{
                            userVPNInfo.pre_shared_key_ascii
                          }}</strong>
                        </div>
                      </b-row>
                      <b-row class="mt-1" v-if="userVPNInfo.hostname">
                        <div class="col-12 col-lg-4 text-lg-right">
                          Server address
                        </div>
                        <div class="col-12 col-lg-8">
                          <strong>{{ userVPNInfo.hostname }}</strong>
                        </div>
                      </b-row>
                      <b-row class="mt-1" v-if="userVPNInfo.username">
                        <div class="col-12 col-lg-4 text-lg-right">
                          Username
                        </div>
                        <div class="col-12 col-lg-8">
                          <strong>{{ userVPNInfo.username }}</strong>
                        </div>
                      </b-row>
                      <b-row class="mt-1" v-if="userVPNInfo.password">
                        <div class="col-12 col-lg-4 text-lg-right">
                          Password
                        </div>
                        <div class="col-12 col-lg-8">
                          <strong>{{ userVPNInfo.password }}</strong>
                        </div>
                      </b-row>
                    </b-alert>
                    <p>
                      5. Tap
                      <strong>Save</strong>
                    </p>
                    <p>
                      6.
                      <a
                        href="#"
                        @click.prevent="
                          showCertDownloadInfoForAndroid = true;
                          loadUserConfigAccessToken();
                        "
                        >Click here</a
                      >
                      if you wish to use the Decrypted Mode, for Android version
                      &lt; 7.0.
                    </p>
                    <b-alert
                      :show="showCertDownloadInfoForAndroid"
                      ref="cert-download-info-android"
                      variant="light"
                    >
                      <p>
                        6-a. Scan the QR code or
                        <a
                          href="#"
                          target="_blank"
                          @click.prevent="downloadUserCertificate"
                          >click here</a
                        >
                        to download the certificate.
                      </p>
                      <div class="mb-2">
                        <qrcode-vue
                          :value="userCADownloadUrl"
                          renderAs="svg"
                          @click="loadUserConfigAccessToken"
                          :size="optimalQRCodeSize"
                          level="M"
                        ></qrcode-vue>
                      </div>
                      <p>
                        6-b. Install the certificate on the device. See the
                        <a
                          href="https://support.google.com/pixelphone/answer/2844832"
                          target="_blank"
                          >detailed instructions</a
                        >
                        by Google.
                      </p>
                    </b-alert>
                  </div>
                  <div v-show="selectedDevice === 'ios'">
                    <div class="mb-3 rounded-lg bg-light">
                      Quick jump to
                      <a
                        href="#"
                        @click.prevent="
                          $refs.deviceConfigiOSSlideShow.setSlide(1)
                        "
                        >A-1. Download the VPN configuration</a
                      >
                      |
                      <a
                        href="#"
                        @click.prevent="
                          $refs.deviceConfigiOSSlideShow.setSlide(11)
                        "
                        >B-1. Download the certificate</a
                      >
                    </div>
                    <b-carousel
                      ref="deviceConfigiOSSlideShow"
                      class="device-config-slides"
                      :interval="0"
                      img-width="640"
                      img-height="480"
                      controls
                      indicators
                      @sliding-end="deviceConfigiOSSlideChanged"
                    >
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide1.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide2.jpg"
                      >
                        <b-row class="mb-3">
                          <div class="offset-7 col-5">
                            <a
                              :href="userMobileConfigDownloadUrl"
                              target="_blank"
                            >
                              <qrcode-vue
                                :value="userMobileConfigDownloadUrl"
                                renderAs="svg"
                                :size="optimalQRCodeSize"
                                level="M"
                              ></qrcode-vue>
                            </a>
                          </div>
                        </b-row>
                      </b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide3.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide4.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide5.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide6.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide7.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide8.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide9.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide10.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide11.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide12.jpg"
                      >
                        <b-row class="mb-3">
                          <div
                            class="offset-7 col-5"
                            @click="loadUserConfigAccessToken"
                          >
                            <a :href="userCADownloadUrl" target="_blank">
                              <qrcode-vue
                                :value="userCADownloadUrl"
                                renderAs="svg"
                                :size="optimalQRCodeSize"
                                level="M"
                              ></qrcode-vue>
                            </a>
                          </div>
                        </b-row>
                      </b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide13.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide14.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide15.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide16.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide17.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide18.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide19.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide20.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide21.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide22.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide23.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide24.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide25.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide26.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide27.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide28.jpg"
                      ></b-carousel-slide>
                      <b-carousel-slide
                        img-src="../assets/config_steps_ios/slide29.jpg"
                      ></b-carousel-slide>
                    </b-carousel>
                    <div class="mt-3">
                      <small>
                        <p class="text-muted">
                          If you wish to manually configure your iOS device
                          instead of using an automated configuration file,
                          please
                          <a
                            href="#"
                            @click.prevent="
                              loadUserVPNInfo();
                              selectedDevice = 'other';
                            "
                            >click here</a
                          >
                          for the general information about VPN connection for
                          all other operating systems.
                        </p>
                      </small>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div class="row justify-content-center mt-3">
              <div class="col-5">
                <button
                  type="button"
                  class="btn btn-block btn-lg btn-outline-secondary"
                  @click="previousStep"
                >
                  Back
                </button>
              </div>
              <div class="col-5">
                <button
                  type="button"
                  class="btn btn-block btn-lg btn-secondary"
                  @click="nextStep"
                >
                  Done
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </b-row>

    <b-row class="row" v-show="step === 5">
      <div class="col-12 col-md-11">
        <div class="card box-shadow mb-2">
          <div class="card-header text-center">
            <h4>Ready to record</h4>
          </div>
          <div class="card-body">
            <div class="record-device-traffic-description text-center">
              <div class="row justify-content-center">
                <div
                  class="col-10 col-sm-5 text-left text-sm-right align-middle"
                >
                  Mode
                </div>
                <div class="col-10 col-sm-7 text-left text-sm-left">
                  <strong>{{ humaniseText(selectedRecordModeText) }}</strong>
                </div>
              </div>
              <div class="row justify-content-center mt-2">
                <div
                  class="col-10 col-sm-5 text-left text-sm-right align-middle"
                >
                  Traffic Entry
                </div>
                <div class="col-10 col-sm-7 text-left text-sm-left">
                  <strong>{{ selectedEntryNodeName }}</strong>
                </div>
              </div>
              <div class="row justify-content-center mt-2">
                <div
                  class="col-10 col-sm-5 text-left text-sm-right align-middle"
                >
                  Traffic Exit
                </div>
                <div class="col-10 col-sm-7 text-left text-sm-left">
                  <strong>{{ selectedExitNodeName }}</strong>
                </div>
              </div>
              <div class="row justify-content-center mt-2">
                <div
                  class="col-10 col-sm-5 text-left text-sm-right align-middle"
                >
                  Session Name
                </div>
                <div class="col-10 col-sm-7 text-left text-sm-left">
                  <strong>{{ sessionName }}</strong>
                </div>
              </div>
              <div class="row justify-content-center mt-4">
                <div class="col-10 col-md-6">
                  <button
                    type="button"
                    class="btn btn-block btn-lg btn-danger"
                    @click="nextStep"
                  >
                    <b-icon icon="camera-video-fill"></b-icon>&nbsp;Start
                    recording
                  </button>
                </div>
              </div>
              <div class="row justify-content-center mt-3">
                <b-alert
                  class="col-10 col-sm-6 mt-2"
                  show
                  variant="info"
                  dismissible
                >
                  <b-row>
                    <b-col class="col-12 col-sm-3 align-middle">
                      <b-icon
                        icon="exclamation-circle-fill"
                        font-scale="1.5"
                      ></b-icon>
                      <br />
                      <b-icon icon="toggle-off" font-scale="2.5"></b-icon>
                    </b-col>
                    <b-col class="col-12 col-sm-9">
                      <small>
                        Please
                        <strong>DO NOT</strong>&nbsp;switch on the VPN
                        connection until you are asked to do so in the next step
                      </small>
                    </b-col>
                  </b-row>
                </b-alert>
              </div>
            </div>
          </div>
        </div>
      </div>
    </b-row>

    <b-row class="row" v-show="step === 6">
      <div class="col-12 col-md-11">
        <div class="card box-shadow mb-2">
          <div class="card-header text-center">
            <h4>{{ recordingStatusText }}</h4>
          </div>
          <div class="card-body">
            <div class="record-device-traffic-description text-center">
              <div class="row justify-content-center">
                <div
                  class="col-12 text-center text-danger display-3 timer"
                  @click="getRecordingStatusUpdate"
                >
                  {{ recordingMainDisplayText }}
                </div>
              </div>
              <div class="row justify-content-center mt-2">
                <div
                  class="col-12 col-md-6"
                  v-show="recordMode === 'decrypted' && recordingInProgress"
                >
                  <a
                    class="btn btn-block btn-lg btn-secondary mt-2"
                    :href="viewLiveTrafficLink"
                    target="_blank"
                  >
                    <b-icon icon="eye"></b-icon>&nbsp;View live traffic
                  </a>
                </div>
                <div class="col-12 col-md-6">
                  <button
                    type="button"
                    class="btn btn-block btn-lg btn-outline-danger mt-2"
                    :disabled="!recordingInProgress"
                    @click="stopRecording"
                  >
                    <b-icon icon="camera-video-off"></b-icon>&nbsp;End recording
                  </button>
                </div>
              </div>
              <div
                class="row justify-content-center mt-4"
                v-show="recordingInProgress"
              >
                <b-alert
                  class="col-10 col-sm-6 mt-2"
                  show
                  variant="success"
                  dismissible
                >
                  <b-row>
                    <b-col class="col-12 col-sm-3 align-middle">
                      <b-icon icon="toggle-on" font-scale="2.5"></b-icon>
                    </b-col>
                    <b-col class="col-12 col-sm-9">
                      <small>
                        Now please switch <strong>ON</strong> the VPN connection to
                        <strong>{{ selectedEntryNodeName }}</strong>
                        on your device
                      </small>
                    </b-col>
                  </b-row>
                </b-alert>
              </div>
              <div
                class="row justify-content-center mt-4"
                v-show="!recordingInProgress"
              >
                <b-alert
                  class="col-10 col-sm-6 mt-2"
                  show
                  variant="info"
                  dismissible
                >
                  <b-row>
                    <b-col class="col-12 col-sm-3 align-middle">
                      <!--<b-icon
                        icon="exclamation-circle-fill"
                        font-scale="1.5"
                      ></b-icon>
                      <br />-->
                      <b-icon icon="toggle-off" font-scale="2.5"></b-icon>
                    </b-col>
                    <b-col class="col-12 col-sm-9">
                      <small>
                        Please keep the VPN connection <strong>OFF</strong>
                      </small>
                    </b-col>
                  </b-row>
                </b-alert>
              </div>
            </div>
          </div>
        </div>
      </div>
    </b-row>

    <b-row>
      <b-alert
        class="col-12 col-sm-11"
        v-model="showErrorAlert"
        variant="danger"
        dismissible
        >{{ errorMessage }}</b-alert
      >
    </b-row>
  </b-container>
</template>

<script>
import QrcodeVue from "qrcode.vue";
import axios from "axios";
import uiResources from "../resources/default";
import componentHeader from "../components/ComponentHeader";

export default {
  components: {
    QrcodeVue,
    componentHeader,
  },
  data: function () {
    return {
      recordMode: null,
      selectedExitNode: null,
      selectedEntryNode: null,
      selectedDevice: null,
      sessionName: null,
      step: 1,
      configFileAccessToken: null,
      availableExitNodes: [],
      availableEntryNodes: [],
      //userPrivileges: [],
      userVPNInfo: null,
      recordingMainDisplayText: "00:00:00:00",
      showErrorAlert: false,
      showCertDownloadInfoForAndroid: false,
      errorMessage: "",
      recordingSessionId: null,
      recordingSessionStatus: null,
      recordingInProgress: false,
      sessionStatusPollInteralMS: 2500,
      optimalQRCodeSize: 200,
      deviceConfigiOSSlide: 0,
    };
  },
  methods: {
    nextStep: function (arg) {
      if (!this.$parent.isLoggedIn) {
        this.$router.push({ name: "Login", query: { destination: "Record" } });
        return;
      }
      if (this.step === 1) {
        this.recordMode = arg;
        this.step++;
      } else if (this.step === 3) {
        this.selectedDevice = arg;
        if (["android", "other"].includes(this.selectedDevice)) {
          this.loadUserVPNInfo();
        } else if (this.selectedDevice === "ios") {
          this.updateQRCodeOptimalSize();
        }
        if (this.selectedDevice === "skip") {
          this.step = 5;
        } else {
          this.step++;
        }
      } else if (this.step === 5) {
        this.startRecording();
      } else if (this.step < 6) {
        this.step++;
      }
    },
    previousStep: function () {
      if (this.step > 0) {
        this.step--;
        if (this.step === 1) {
          this.recordMode = null;
        } else if (this.step === 2 && this.recordMode != "decrypted") {
          this.step--;
        }
      }
    },
    stopRecording: function () {
      if (this.recordingSessionId) {
        axios
          .post(`/session/${this.recordingSessionId}/stop`)
          .then((result) => {
            if (result.data.returned) {
              this.recordingInProgress = false;
            } else if (result.data.errorMessage) {
              this.errorMessage = result.data.errorMessage;
              this.showErrorAlert = true;
            }
          });
      }
    },
    startRecording: function () {
      axios
        .post("/recording/start", {
          exitNodeId: this.selectedExitNode,
          mode: this.recordMode,
          sessionName: this.sessionName,
        })
        .then((result) => {
          if (result.data.returned) {
            this.recordingSessionId = result.data.returned;
            this.step = 6;
            this.startRecordingStatusPolling();
            this.startRecordingDisplayTimer();
          } else if (result.data.errorMessage) {
            this.errorMessage = result.data.errorMessage;
            this.showErrorAlert = true;
          }
        });
    },
    startRecordingStatusPolling: function () {
      if (this.sessionStatusPollInteralMS > 0) {
        if (this.recordingSessionId) {
          this.getRecordingStatusUpdate();
          setTimeout(
            this.startRecordingStatusPolling,
            this.sessionStatusPollInteralMS
          );
        }
      }
    },
    startRecordingDisplayTimer: function () {
      if (this.recordingInProgress) {
        if (this.recordingSessionStatus.exitNodeCreated) {
          this.recordingMainDisplayText = uiResources.timeDifferenceText(
            new Date(this.recordingSessionStatus.exitNodeCreated),
            new Date()
          );
        }
      }
      setTimeout(this.startRecordingDisplayTimer, 1000);
    },
    getRecordingStatusUpdate: function () {
      if (this.recordingSessionId) {
        axios
          .get(`/session/${this.recordingSessionId}/status`)
          .then((result) => {
            this.recordingSessionStatus = result.data.returned;
            this.handleRecordingStatsUpdate();
          });
      }
    },
    handleRecordingStatsUpdate: function () {
      let isRecordingInProgress = false;
      if (this.recordingSessionStatus) {
        this.recordMode = this.recordingSessionStatus.mode;
        if (this.recordingSessionStatus.status === "recording") {
          isRecordingInProgress = true;
          this.sessionStatusPollInteralMS = 10000;
        } else if (this.recordingSessionStatus.status === "ended") {
          this.sessionStatusPollInteralMS = -1;
          this.$router.push({ name: "Sessions" });
          return;
        } else {
          this.sessionStatusPollInteralMS = 2500;
        }
      }
      this.recordingInProgress = isRecordingInProgress;
    },
    recordOptionEnabled: function (recordOptionName) {
      if (!this.$parent.isLoggedIn) {
        /* Make it appear inviting to the users when not logged in by showing all available options.  Unauthenticated users will be automatically taken to the log in page.   */
        return true;
      }
      /* Disable the options which are not available to the user */
      //return ["raw", "metadata"].includes(recordOptionName);
      return this.$parent.userPrivileges.includes(recordOptionName);
    },
    loadUserConfigAccessToken: function () {
      axios.get("/user/config_access_token").then((result) => {
        this.configFileAccessToken = result.data.returned;
      });
    },
    loadUserVPNInfo: function () {
      axios.get(`/user/vpn_info/${this.selectedEntryNode}`).then((result) => {
        this.userVPNInfo = result.data.returned;
      });
    },
    updateQRCodeOptimalSize: function () {
      if (this.$refs.recordContainer)
        this.optimalQRCodeSize = Math.floor(
          this.$refs.recordContainer.offsetWidth / 5
        );
      else this.optimalQRCodeSize = Math.floor(window.innerWidth / 6);
    },
    onWindowSizeChanged: function () {
      if (this.step === 4 && this.selectedDevice === "ios") {
        this.updateQRCodeOptimalSize();
      }
    },
    deviceConfigiOSSlideChanged: function () {
      if ([1, 11].includes(this.$refs.deviceConfigiOSSlideShow.index)) {
        this.loadUserConfigAccessToken();
        this.updateQRCodeOptimalSize();
      }
    },
    downloadUserCertificate: function () {
      axios.get("/user/config_access_token").then((result) => {
        if (result.data.returned) {
          var downloadLink = document.createElement("a");
          downloadLink.href =
            axios.defaults.baseURL + `/cert/${result.data.returned}`;
          downloadLink.target = "_blank";
          downloadLink.click();
        }
      });
      return;
    },
    humaniseText: function(text) {
      if (text) 
        return uiResources.humaniseText(text);
      else 
        return "";
    },
  },
  computed: {
    userMobileConfigDownloadUrl: function () {
      if (this.configFileAccessToken) {
        return (
          axios.defaults.baseURL + `mobileconfig/${this.configFileAccessToken}`
        );
      }
      return "about:blank";
    },
    userCADownloadUrl: function () {
      if (this.configFileAccessToken) {
        return axios.defaults.baseURL + `cert/${this.configFileAccessToken}`;
      }
      return "about:blank";
    },
    exitNodeOptionList: function () {
      if (this.availableExitNodes) {
        if (this.availableExitNodes.length > 0) {
          return this.availableExitNodes.map((n) => {
            return { text: n.nodeName, value: n.nodeId };
          });
        }
      }
      return [];
    },
    entryNodeOptionList: function () {
      if (this.availableEntryNodes) {
        if (this.availableEntryNodes.length > 0) {
          return this.availableEntryNodes.map((n) => {
            return { text: n.nodeName, value: n.nodeId };
          });
        }
      }
      return [];
    },
    selectedExitNodeName: function () {
      if (this.selectedExitNode && this.availableExitNodes.length > 0) {
        let selectedNode = this.availableExitNodes.find(
          (n) => n.nodeId == this.selectedExitNode
        );
        if (selectedNode) {
          return selectedNode.nodeName;
        }
      }
      return "";
    },
    selectedEntryNodeName: function () {
      if (this.recordingSessionStatus) {
        if (this.recordingSessionStatus.entryNodeName) {
          return this.recordingSessionStatus.entryNodeName;
        }
      } else {
        let selectedNode = this.availableEntryNodes.find(
          (n) => n.nodeId == this.selectedEntryNode
        );
        if (selectedNode) {
          return selectedNode.nodeName;
        }
      }
      return "the selected entry node";
    },
    selectedRecordModeText: function () {
      if (this.recordMode) {
        if (Object.keys(uiResources.recordingModes).includes(this.recordMode))
          return uiResources.recordingModes[this.recordMode];
      }
      return "";
    },
    recordingStatusText: function () {
      if (this.recordingSessionStatus) {
        if (
          Object.keys(uiResources.recordingStatuses).includes(
            this.recordingSessionStatus.status
          )
        ) {
          var statusText =
            uiResources.recordingStatuses[this.recordingSessionStatus.status];
          if (!this.recordingInProgress) {
            statusText = `Please wait ... ${statusText}`;
          }
          return uiResources.humaniseText(statusText);
        }
      }
      return "Please wait ...";
    },
    viewLiveTrafficLink: function () {
      if (this.recordMode)
        if (this.recordMode === "decrypted")
          if (this.recordingSessionStatus)
            if (
              this.recordingSessionStatus.exit_node_public_hostname &&
              this.recordingSessionStatus.mitm_web_port
            )
              return `http://${this.recordingSessionStatus.exit_node_public_hostname}:${this.recordingSessionStatus.mitm_web_port}/`;
      return "about:blank";
    },
  },
  mounted: function () {
    if (this.$parent.isLoggedIn) {
      axios.get("/node/all").then((result) => {
        if (result.data.returned) {
          this.availableExitNodes = result.data.returned.exit;
          this.availableEntryNodes = result.data.returned.entry;
          /* select default entry and exit nodes */
          if (this.availableExitNodes.length > 0) {
            this.selectedExitNode = this.availableExitNodes[0].nodeId;
          }
          if (this.availableEntryNodes.length > 0) {
            this.selectedEntryNode = this.availableEntryNodes[0].nodeId;
          }
        }
      });
      
      /*axios.get("/user/privileges").then((result) => {
        this.userPrivileges = result.data.returned;
      });*/

      if (this.$route.query.id) {
        this.recordingSessionId = this.$route.query.id;
      } else if (this.$route.params.sessionId) {
        this.recordingSessionId = this.$route.params.sessionId;
      }
      if (this.recordingSessionId) {
        this.step = 6;
        this.startRecordingStatusPolling();
        this.startRecordingDisplayTimer();
      }
    }

    window.addEventListener("resize", this.onWindowSizeChanged);
  },
  beforeDestroy: function () {
    this.sessionStatusPollInteralMS = -1;
  },
};
</script>

<style scoped>
.record-mode-description {
  height: 16em;
}

.record-mode-note {
  line-height: 1;
}

.system-selection-button {
  background-color: Transparent;
  border-width: thick;
}

.system-selection-icon {
  filter: blur(0.3px) opacity(40%) hue-rotate(30deg);
}

.device-config-slides {
  background: #a0a0a0;
}
</style>
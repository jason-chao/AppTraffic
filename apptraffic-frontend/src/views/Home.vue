<template>
  <b-container>
    <div class="position-relative overflow-hidden p-3 p-md-5 m-md-3 text-center bg-light">
      <div class="col-md-5 p-lg-5 mx-auto my-5">
        <h1 class="display-3 font-weight-normal">AppTraffic</h1>
        <p class="lead font-weight-normal">
          The easiest tool to capture, inspect and playback the traffic of
          mobile apps
        </p>
        <a class="btn btn-outline-secondary" href="#">Learn more</a>
      </div>
      <div class="product-device box-shadow d-none d-lg-block"></div>
      <div class="product-device product-device-2 box-shadow d-none d-lg-block"></div>
    </div>
  </b-container>
</template>

<script>
</script>

<style scoped>
.product-device {
    position: absolute;
    right: 10%;
    bottom: -30%;
    width: 300px;
    height: 540px;
    background-color: #333;
    border-radius: 21px;
    -webkit-transform: rotate(30deg);
    transform: rotate(30deg);
  }
  
  .product-device::before {
    position: absolute;
    top: 10%;
    right: 10px;
    bottom: 10%;
    left: 10px;
    content: "";
    background-color: rgba(255, 255, 255, .1);
    border-radius: 5px;
  }
  
  .product-device-2 {
    top: -25%;
    right: auto;
    bottom: 0;
    left: 5%;
    background-color: #e5e5e5;
  }
</style>

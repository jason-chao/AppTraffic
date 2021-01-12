<template>
  <b-container class="mb-3">
    <b-row>
      <h3>{{title}}</h3>
    </b-row>
  </b-container>
</template>

<script>

export default {
    props: {
        title: String
    }
}
</script>
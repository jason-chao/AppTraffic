import Vue from 'vue'
import VueRouter from 'vue-router'
import Home from '../views/Home.vue'
import About from '../views/About.vue'
import Signup from '../views/Signup.vue'
import Login from '../views/Login.vue'
import Record from '../views/Record.vue'
import Sessions from '../views/Sessions.vue'
import Summary from '../views/Summary.vue'

Vue.use(VueRouter)

const routes = [
  {
    path: '/',
    name: 'Home',
    component: Home
  }, {
    path: '/about',
    name: 'About',
    component: About
  }, {
    path: '/record',
    name: 'Record',
    component: Record
  }, {
    path: '/sessions',
    name: 'Sessions',
    component: Sessions
  }, {
    path: '/signup',
    name: 'Signup',
    component: Signup
  }, {
    path: '/login',
    name: 'Login',
    component: Login
  }, {
    path: '/summary',
    name: 'Summary',
    component: Summary
  }
]

const router = new VueRouter({
  routes
})

export default router

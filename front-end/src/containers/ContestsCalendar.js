import React, { Component } from 'react';
import ReactDOM from 'react-dom';
import { BrowserRouter, Switch, Route, NavLink } from 'react-router-dom'
import { Redirect } from 'react-router'
import moment from 'moment';
import BigCalendar from 'react-big-calendar';



//*******************const**********************//
const io = require('socket.io-client')
const socket = io()
BigCalendar.setLocalizer(
  BigCalendar.momentLocalizer(moment)
);

export default class ContestCalendar extends Component {


componentDidMount() {

  socket.on('contests', function (data) {
     console.log(data);
     socket.emit('my other event', { my: 'data' });
   });
}


  render() {
    return (
      <div>




      </div>
    );
  }
}

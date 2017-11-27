import {
  default as React,
  Component,
} from 'react';

import { GoogleMap, Marker,withGoogleMap, } from 'react-google-maps';


export  const  SimpleMapExampleGoogleMap = withGoogleMap(props => (
  <GoogleMap
    defaultZoom={16}
    defaultCenter={{ lat: -34.397, lng: 150.644 }}
  />
));

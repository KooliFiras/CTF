import React, { Component } from 'react';
import { NavLink,Link } from 'react-router-dom';
import axios from 'axios';
import { DropdownButton,MenuItem } from 'react-bootstrap';

export default class FilterButton extends Component {




constructor(props) {
      super(props);
      this.state = {
      users :[]
      };
    }



//******handle select*************//
handleSelect=(evt)=> {
        // what am I suppose to write in there to get the value?
        console.log(evt)
        console.log('even seleetc');
      this.props.sortData(evt);
    }









  render() {
    return (
      <DropdownButton title="Sort Data" id="bg-nested-dropdown"
        onSelect={(event) => this.handleSelect(event)}>
         <MenuItem eventKey="python">Python</MenuItem>
         <MenuItem eventKey="webserver">Web Server</MenuItem>
       </DropdownButton>
    );
  }
}

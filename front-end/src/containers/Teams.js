import React, { Component } from 'react';

export default class Teams extends Component {




  constructor(props) {
    super(props);
    this.state = {

    };
  }


  render() {
    return (
      <div className="container">
  <h2>List f Teams </h2>

  <table className="table table-bordered">
    <thead>
      <tr>
        <th>Team name</th>
        <th>Score</th>

      </tr>
    </thead>
    <tbody>
      <tr>
        <td>John</td>
        <td>Doe</td>

      </tr>
      <tr>
        <td>Mary</td>
        <td>Moe</td>

      </tr>
      <tr>
        <td>July</td>
        <td>Dooley</td>
      
      </tr>
    </tbody>
  </table>
</div>
    );
  }
}

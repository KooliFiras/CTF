import React, { Component } from 'react';
import { NavLink,Link } from 'react-router-dom';
import axios from 'axios';
import FilterButton from '../components/FilterButton'


export default class Leaderboard extends Component {




constructor(props) {
      super(props);
      this.state = {
      users :[]
      };
    }




componentDidMount() {
   axios.get(`url of users`)
        .then(res => {
           console.log('result from server' + res);
          //this.setState({ posts });
        }).catch(err=>{
          console.log('er in fecthing data');
        })
    }



//***********sort the data ************//
sortData =(e)=>{
  console.log('data from children' + e);
  console.log('we will sort data');
}




  render() {
    return (
<div className="container bounceInRight">


<div className="row">
  <h3 className="text-center"> Leaderboard </h3>
</div>
<div className="row">
  <FilterButton sortData={this.sortData} />
</div>


<br/>
<br/>
<br/>



<div className="row">

<div className="col-md-9">

<table className="table table-striped">
<thead>
            <tr>
            <td className="active">Rank</td>
          <td className="active">Hacker</td>
          <td className="active">Points</td>
          <td className="active">University</td>

         </tr>
</thead>

<tbody>
            <tr>
             <td> 1 </td>
             <td>
                 <Link to="/UserProfile" activeClassName="active">
                   hacker foulen ben foulen
                 </Link>
                </td>
             <td> 125.0 </td>
             <td> Cartaghe </td>
            </tr>


            <tr>
             <td> 1 </td>
             <td> hacker foulen ben foulen </td>
             <td> 125.0 </td>
             <td> Cartaghe </td>
            </tr>

            <tr>
             <td> 1 </td>
             <td> hacker foulen ben foulen </td>
             <td> 125.0 </td>
             <td> Cartaghe </td>
            </tr>
</tbody>
</table>


</div>


<div className="col-md-3">
  <button type="button" className="btn">Basic</button>
<button type="button" className="btn btn-default">Default</button>
<button type="button" className="btn btn-primary">Primary</button>
<button type="button" className="btn btn-success">Success</button>
<button type="button" className="btn btn-info">Info</button>
<button type="button" className="btn btn-warning">Warning</button>
<button type="button" className="btn btn-danger">Danger</button>
<button type="button" className="btn btn-link">Link</button>
</div>

</div>




      </div>
    );
  }
}

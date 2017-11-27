import React, { Component } from 'react';
import ProblemCategory from '../components/ProblemCategory' ;
import axios from 'axios';
import { Button,Breadcrumb } from 'react-bootstrap';
import  DatePicker from 'react-bootstrap-date-picker' ;

export default class CreateContest extends Component {




constructor(props) {
        super(props);
        this.state = {
       name :'',
       start_date :'',
       end_date :'',
       start_time :'',
       end_time :'',
       organisation_name :'',
       organisation_type :''



        };
      }



componentWillMount()
{
        //********here we will GET DATA from redux to chekc if user authenticated o
        //********not
}



//***************function to validate ContestName********************//

CheckContestName = (e )=>
{

}

//********function to validate ContestStartDate******************//
CheckContestStartDay =(e)=>{

}


//************function to validate ContestEndDate**********************//
CheckContestEndDay =()=>{

}

//************functio to validate ContestStartTime**************//
CheckStartTime =()=>{

}

//*************function to validate CheckEndTime***************//
CheckEndTime =()=>{

}

//*************function to validate Organisation Name ***************//
CheckOrganisationName =()=>{

}




CreateContest =()=>{
console.log('clciked to create a problem');
console.log('pressed');
this.props.history.push('/CreateContest/AddChallenge')


}

//******************************//





  render() {
const {pathname} = this.props.location;
    return (
<div className="container">


  <div class="row">

  <div class="alert alert-light" role="alert">
      Create Contest
  </div>

  </div>

<hr/>


<br/>















<div className="row">

  <form className="form-inline" onSubmit={this.CreateContest} noValidate>

<div className="row">
    <div className="form-group">
      <label for="contest" className="text-right">Contest Name * </label>
      <input value={this.state.name}
      onChange={(event) => this.CheckContestName(event)}
         type="text" className="form-control" id="contest" />

    </div>
</div>

<br/>



<div className="row">

<div className="col-md-4">

    <div className="form-group">
      <label for="start">Start Time * </label>
      <input
onChange={(event) => this.CheckContestStartDay(event)}
         value={this.state.satrt_date} type="date" className="form-control" id="start" />
     </div>
</div>


<div className="col-md-4">

    <div className="form-group">
      <label for="time">  at * </label>
      <input
onChange={(event) => this.CheckContestStartDay(event)}
         value={this.state.start_hour} type="datetime-local" className="form-control" id="time" />
    </div>
</div>


</div>

<br/>


<div className="row">

<div className="col-md-4">

    <div className="form-group">
      <label for="endtime">End Time * </label>
      <input
onChange={(event) => this.CheckContestStartDay(event)}
         value={this.state.end_date} type="date" className="form-control" id="endtime" />
     </div>
</div>

<div className="col-md-4">

    <div className="form-group">
      <label for="endhour">at * </label>
      <input
onChange={(event) => this.CheckContestStartDay(event)}
         value={this.state.end_hour} type="datetime-local" className="form-control" id="endhour" />
    </div>
</div>


</div>

<br/>



<div className="row">

<div className="form-group">
  <div className="col-md-6">
    <label for="email">  Organisation Type </label>
    </div>

    <div className="col-md-4">
    <select
onChange={(event) => this.CheckContestStartDay(event)}
       value={this.state.orgniasation_type} className="form-control" id="sel1">
      <option> </option>
     <option value="Company">Company</option>
     <option value="School">School</option>
     <option value="Non-profit">Non Profit</option>
     <option value="Other">Other</option>
   </select>
 </div>
</div>

</div>


<br/>





  <div className="row">
      <div className="form-group">
        <label for="contest" className="text-right">Orgnaisation Name * </label>
        <input
          onChange={(event) => this.CheckContestStartDay(event)}
           value={this.state.orgniasation_name} type="text" className="form-control" id="contest" />

      </div>
  </div>



<br/>






<div className="row">

  <button type="submit"


     className="btn btn-success">Next <i className="fa fa-arrow-right" aria-hidden="true"></i> </button>
</div>


  </form>
</div>



        </div>
    );
  }
}

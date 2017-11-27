
import React, { PropTypes } from 'react'


export default class ErrorMsg  extends React.Component {


  constructor(props) {
        super(props);

      }



  render () {
    let msg = this.props.children

      return (
        <div className="alert alert-danger bounceInRight">
       <p> {msg} </p>
        </div>
      )



  }
}

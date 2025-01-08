exports.handler = async () => {
    const maintenanceMode = process.env.MAINTENANCE_MODE || 'FALSE';
  
    return {
      statusCode: 200,
      body: JSON.stringify({ maintenanceMode })
    };
  };

  //add below code to index html in head section below title by removing comment if you want to use the maintenance mode in your app
  //<script>
        //fetch('/.netlify/functions/get-maintenance-mode')
        //  .then(response => response.json())
          //.then(data => {
          //  if (data.maintenanceMode === 'FALSE') {
        //      window.location.href = "/maintenance.html";
          //  }
        //  })
        //  .catch(error => console.error('Error fetching maintenance mode:', error));
     // </script>
  
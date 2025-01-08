exports.handler = async () => {
    const maintenanceMode = process.env.MAINTENANCE_MODE || 'FALSE';
  
    return {
      statusCode: 200,
      body: JSON.stringify({ maintenanceMode })
    };
  };
  
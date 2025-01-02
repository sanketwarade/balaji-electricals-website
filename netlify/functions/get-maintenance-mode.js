exports.handler = async () => {
    const maintenanceMode = process.env.MAINTENANCE_MODE || 'TRUE';
  
    return {
      statusCode: 200,
      body: JSON.stringify({ maintenanceMode })
    };
  };
  
#!/usr/bin/env node

const axios = require('axios');
const fs = require('fs');
const fsp = require('fs').promises;
const yaml = require('js-yaml');

async function readContrastConfig(filePath) {
  return new Promise((resolve, reject) => {
    fs.readFile(filePath, 'utf8', (err, data) => {
      if (err) reject(err);
      else resolve(yaml.load(data));
    });
  });
}
  

async function getContrastData(url) {
  try {
    const response = await axios.get(url, {
      headers: {
        Authorization: auth,
        'API-Key': apiKey,
        Accept: 'application/json',
      },
    });
    return response.data;
  } catch (error) {
    console.error(error);
    return null;
  }
}

async function listApps() {
  console.log('Select from the following list of applications, and try again');
  const data = await getContrastData(appsUrl);
  const apps = data.applications;
  for (const app of apps) {
    console.log('  ' + app.name);
  }
}

async function getVulnerabilityCount(appId) {
  // const vulnUrl = `${contrastUrl}/api/v4/organizations/${orgId}/applications/${appId}/vulnerabilities`;
  const vulnUrl = `${contrastUrl}/api/ng/${orgId}/traces/${appId}/quick`;
  const response = await getContrastData(vulnUrl);
  return response.filters[0].count;
}

function getRouteCoverage( routes ) {
  let urls = '';
  let exercised = 0;
  for (const route of routes) {
    if ( route.exercised != null ) {
      exercised++;
    }
  }
  const coverage = exercised / routes.length;
  const result = (coverage * 100).toFixed(1) + '%  (' + exercised + '/' + routes.length + ')';
  return result;
}


//==================================================== 


const crawlerExecutablePath = 'zap/Java/zap.sh';
const crawlerApiPort = 8080;
const crawlerApiKey = 'jeff';
const crawlerApiBaseUrl = `http://localhost:${crawlerApiPort}/JSON`;

const { exec } = require('child_process');

function startCrawlerApi() {

  // this is the goal -- not working
  // NOTE: port changes don't seem to work with importing urls - must be 8080
  // ./zap/Java/zap.sh -daemon -newsession contrast -config proxy.port=8080 -config api.key=jeff

  exec( crawlerExecutablePath + ` -daemon -config proxy.port=8080 -config api.key=${crawlerApiKey}` );
 }

async function isCrawlerApiReady() {
  while (true) {
    try {
      const zapApiUrl = `${crawlerApiBaseUrl}/core/view/version/`;
      const response = await axios.get(zapApiUrl, {
        params: {
          apikey: crawlerApiKey,
        },
      });
        if (response.status === 200) {
        return response.data;
      }
    } catch (error) {
      // Handle error silently and continue the loop
    }
    console.log( " ... waiting" );
    await new Promise(res => setTimeout(res, 2000)); // Wait for 2 seconds before next try
  }
}


async function configureCrawler(path, appName) {
  // try {
    // http://localhost:8080/JSON/context/action/importContext/?apikey=jeff&contextFile=%2FUsers%2Fjeffwilliams%2Fgit%2Falerter%2Fbodgeit.context
    // http://localhost:8080/JSON/context/action/removeContext/?apikey=jeff&contextName=bodgeit 

  //   const crawlerApiUrl1 = `${crawlerApiBaseUrl}/context/action/removeContext/`;
  //   await axios.get(crawlerApiUrl1, {
  //     params: {
  //       apikey: crawlerApiKey,
  //       contextName: `${contextName}`,
  //     },
  //   });
  // } catch (error) {
  //   // expected if context does not already exist
  // }

  try {
    const crawlerApiUrl2 = `${crawlerApiBaseUrl}/context/action/importContext/`;
    console.log ( `creating context ${appName.toLowerCase()}` )
    const response = await axios.get(crawlerApiUrl2, {
      params: {
        apikey: crawlerApiKey,
        contextFile: `${path}/${appName}.context`,
      },
    });
    return response.data;
  } catch (error) {
    console.error('Error configuring crawler: ', error);
  }
}

async function seedCrawler(file) {
  try {
    const crawlerApiUrl = `${crawlerApiBaseUrl}/exim/action/importUrls/`;
    const response = await axios.get(crawlerApiUrl, {
      params: {
        apikey: crawlerApiKey,
        filePath: `${file}`,
      },
    });
    return response.data;
  } catch (error) {
    console.error('Error importing URLs from file: ', error);
  }
}


//http://localhost:8080/JSON/spider/action/scan/?apikey=jeff&url=http%3A%2F%2Flocalhost%3A8081%2Fbodgeit%2F&maxChildren=&recurse=true&contextName=bodgeit&subtreeOnly=
async function startCrawl(url, appName) {
  try {
    if (!url.endsWith('/')) {
      url += '/';
    }
    const contextName = appName.toLowerCase();
    const crawlerApiUrl = `${crawlerApiBaseUrl}/spider/action/scan/`;
    const response = await axios.get(crawlerApiUrl, {
      params: {
        apikey: crawlerApiKey,
        url: `${url}`,
        recurse: true,
        contextName: `${contextName}`,
      },
    });
    return response.data;
  } catch (error) {
    console.error('Error starting crawl: ', error);
  }
}


async function shutdownCrawler() {
  try {
    const crawlerApiUrl = `${crawlerApiBaseUrl}/core/action/shutdown/`;
    const response = await axios.get(crawlerApiUrl, {
      params: {
        apikey: crawlerApiKey,
      },
    });
    return response.data;
  } catch (error) {
    console.error('Error shutting down crawler: ', error);
  }
}

//==================================================== 


async function writeContrastRouteInfoToFile(filename, data) {
  let fileHandle;
  try {
    fileHandle = await fsp.open(filename, 'w');
    await fileHandle.writeFile(data);
  } catch (error) {
    throw error;
  } finally {
    if (fileHandle) {
      await fileHandle.close();
    }
  }
}



function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

//==================================================== 


// FIXME - TODO LIST
// * enable OpenAPI support - https://www.zaproxy.org/blog/2017-04-03-exploring-apis-with-zap/
// * enable authentication support - https://www.zaproxy.org/docs/api/#form-based-authentication:~:text=such%20as%20scanning.-,Steps%20to%20Reproduce%20via%20API,-If%20you%20have
// *      use form, basic, etc.. or ZAP context file
// *      keep it COntrast as much as possible
//
//



const args = process.argv.slice(2);

let contrastUrl = '';
let apiKey = '';
let serviceKey = '';
let userName = '';
let orgId = '';
let auth = '';

let appName = '';
let baseTargetUrl = '';

async function main() {

  if (args.length < 1 || args.length > 1) {
    // await listApps();
    console.log('  Usage: node crawl.js contrast.yaml');
    console.log();
    process.exit();
  }

  // variables to get from CLI
  const filePath = args[0];
  const config = await readContrastConfig(filePath);
  
  contrastUrl = config.api.url;
  apiKey = config.api.api_key;
  serviceKey = config.api.service_key;
  userName = config.api.user_name;
  orgId = config.api.org_id;
  auth = Buffer.from(userName + ':' + serviceKey).toString('base64');
  
  appName = config.application.name;
  baseTargetUrl = config.application.baseUrl;
  
  
  // console.log('API URL:', contrastUrl);
  // console.log('API Key:', apiKey);
  // console.log('Service Key:', serviceKey);
  // console.log('User Name:', userName);
  // console.log('Auth:', auth);
  // console.log('Org Id:', orgId);
  // console.log('App Name:', appName);
  // console.log('App BaseURL:', baseTargetUrl);
  
  

  console.log('Starting crawler engine');
  startCrawlerApi();
  const status = await isCrawlerApiReady();

  const cwd = process.cwd();
  const appsUrl = `${contrastUrl}/api/ng/${orgId}/applications`;
  const data = await getContrastData(appsUrl);
  let appId;
  const apps = data.applications;
  for (const app of apps) {
    if (app.name === appName) {
      appId = app.app_id;
    }
  }

  const routeUrl = `${contrastUrl}/api/ng/${orgId}/applications/${appId}/route`;
  const routeData = await getContrastData(routeUrl);
  const routes = routeData.routes;
  if (routes.length === 0) {
    console.log(`No routes found for application ${appName}. Please send at least one request to the app/API to force it to load`);
    return;
  }

  let urls = '';
  let count = 0;
  for (const route of routes) {
    const sig = route.signature.split('(')[0];
    const hash = route.route_hash;

    const details = await getContrastData(`${routeUrl}/${hash}/observations`);
    const observations = details.observations;
    for (const observation of observations) {
      let verb = observation.verb.trim() || 'GET';
      let path = observation.url || '/';
      path = decodeURIComponent(path);
      const req = `${baseTargetUrl}${path}`;
      urls += req + '\n';
      count++;
    }
  }

  
  try {
    const coverage = getRouteCoverage( routes );
    const vulns = await getVulnerabilityCount( appId );
    console.log ('Before');
    console.log('  Route Coverage:', coverage);
    console.log('  Vulnerabilities:', vulns);
  } catch (error) {
    console.error('Error:', error);
  }

  try {
    await configureCrawler(cwd, appName );
    console.log('Crawler context loaded');
  } catch (error) {
    console.error('Error configuring crawler context:', error);
  }

  try {
    console.log('Seeding crawler with ' + count + ' URLs from Contrast' );
    await writeContrastRouteInfoToFile(cwd + '/contrastRoutes.txt',urls);
  } catch (error) {
    console.error('Error writing seed URL information:', error);
  }

  try {
    console.log('Importing seeds into crawler' );
    const result = await seedCrawler(cwd + '/contrastRoutes.txt' );
  } catch (error) {
    console.error('Error importing seeds into crawler:', error);
  }

  // do a first crawl to visit the seeds
  try {
    const result = await startCrawl(baseTargetUrl, appName);
    console.log(' ... crawling' );
  } catch (error) {
    console.error('Error:', error);
  }

  // do a second crawl to access endopints we learned about in crawl 1
  try {
    const result = await startCrawl(baseTargetUrl, appName);
    console.log(' ... crawling' );
  } catch (error) {
    console.error('Error:', error);
  }

  // wait for routes and vulnerabilities to get reported
  console.log(' ... analyzing' );
  await sleep( 5000 );

  try {
    const routeData = await getContrastData(routeUrl);
    const routes = routeData.routes;

    const coverage = getRouteCoverage(routes);
    const vulns = await getVulnerabilityCount( appId );
    console.log ('After');
    console.log('  Route Coverage:', coverage);
    console.log('  Vulnerabilities:', vulns);
  } catch (error) {
    console.error('Error:', error);
  }

  for (const route of routes) {
    const sig = route.signature.split('(')[0];
    const hash = route.route_hash;

    const details = await getContrastData(`${routeUrl}/${hash}/observations`);
    const observations = details.observations;
    for (const observation of observations) {
      let verb = observation.verb.trim() || 'GET';
      let path = observation.url || '/';
      path = decodeURIComponent(path);
      const req = `${baseTargetUrl}${path}`;
      urls += req + '\n';
    }
  }


  try {
    console.log ('Crawling complete');
    console.log (' ... stopping' );
    console.log();
    const result = await shutdownCrawler();
  } catch (error) {
    console.error('Error:', error);
  }

}



main();





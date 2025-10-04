require('mocha');

global.before = before;
global.after = after;
global.describe = describe;
global.it = it;
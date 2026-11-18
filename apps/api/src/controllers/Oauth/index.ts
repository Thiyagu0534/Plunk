import {ChildControllers, Controller} from '@overnightjs/core';

import {Github} from './Github.js';
import {Google} from './Google.js';
import {Zoho} from './Zoho.js';

@Controller('oauth')
@ChildControllers([new Google(), new Github(), new Zoho()])
export class Oauth {}

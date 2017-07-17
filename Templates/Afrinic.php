<?php
/**
 * Novutec Domain Tools
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @category   Novutec
 * @package    DomainParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\WhoisParser\Templates
 */
namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

/**
 * Template for AFRINIC
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Afrinic extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     * @access protected
     */
    protected $blocks = array(1 => '/(inetnum|inet6num):(?>[\x20\t]*)(.*?)[\r\n]{2}/is',
            2 => '/(person|organisation):(?>[\x20\t]*)(.*?)[\r\n]{2}/is');

    /**
     * Items for each block
     *
     * @var array
     * @access protected
     */
    protected $blockItems = array(
            1 => array('/^inetnum:(?>[\x20\t]*)(.+)$/im' => 'network:inetnum',
                    '/^inet6num:(?>[\x20\t]*)(.+)$/im' => 'network:inetnum',
                    '/^netname:(?>[\x20\t]*)(.+)$/im' => 'network:name',
                    '/^NetHandle:(?>[\x20\t]*)(.+)$/im' => 'network:handle',
                    '/^status:(?>[\x20\t]*)(.+)$/im' => 'status',
                    '/^created:(?>[\x20\t]*)(.+)$/im' => 'created',
                    '/^last-modified:(?>[\x20\t]*)(.+)$/im' => 'changed'),
            2 => array('/^person:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle',
                    '/^organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization',
                    '/^address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address',
                    '/^e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email',
                    '/^country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country',
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone',
                    '/^last-modified:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:changed',
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone',
                    '/^admin-c:(?>[\x20\t]*)(.+)$/im' => 'contacts:abuse:name',
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:abuse:phone',
                    '/^abuse-mailbox:(?>[\x20\t]*)(.+)$/im' => 'contacts:abuse:email'));
}

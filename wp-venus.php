<?php
/*
Plugin Name: WP-Venus
Plugin URI: http://wordpress.org/extend/plugins/wp-venus/
Description: Planet Venus cache syndication - http://www.intertwingly.net/code/venus/
Author: Morten Frederiksen
Author URI: http://www.wasab.dk/morten/
Version: 1.2
*/

/*

Copyright (c) 2006-2008 Morten Frederiksen <morten@wasab.dk>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

*/

function get_venus() {
  static $venus;
  if (!isset($venus))
    $venus = new Venus;
  return $venus;
}

class Venus {

  var $debug;
  var $do_update;
  var $permalink;

  function Venus() {
    $this->debug=false;
    $this->update=false;
    $this->permalink=false;
  }

  function action_admin_menu() {
    if (!current_user_can('edit_plugins') || function_exists('is_site_admin') && !is_site_admin())
      return;
    add_submenu_page("options-general.php", $this->T('Venus'),
                     $this->T('Venus'),
                     8, basename(__FILE__), array(&$this, 'options_venus'));
  }

  function action_delete_post($post_id) {
    $options = get_settings('venus_options');
    list($filename) = get_post_custom_values('venus_cache_file');
    $path = $options['cache_directory'] . DIRECTORY_SEPARATOR . $filename;
    @unlink($path);
  }

  function options_venus() {
    $this->options_venus_checkaction();
    $this->options_venus_display();
  }
  
  function options_venus_checkaction() {
    global $wpdb;
    if (!current_user_can('edit_plugins') || function_exists('is_site_admin') && !is_site_admin())
      return;
    switch ($_POST['action']) {
      case 'do_update':
        /* perform forced update run */
        $count = $this->update(true);
        $this->display_updated('Done updating from cache, '.$count.' new entries were added.');
        break;
      case 'update_options':
        /* update options */
        $options = get_settings('venus_options');
        $options['cache_directory']=$_REQUEST['cache_directory'];
        $options['default_user_role']=$_REQUEST['default_user_role'];
        $options['update_interval']=$_REQUEST['update_interval'];
        $options['tag_with_source']=@$_REQUEST['tag_with_source']?1:0;
        $options['check_entry_size']=@$_REQUEST['check_entry_size']?1:0;
        $options['original_link']=@$_REQUEST['original_link']?1:0;
        $options['last_update']=0;
        update_option('venus_options', $options);
        if ($this->debug)
          $this->log('updated options.');
        $this->display_updated('Options updated.');
        break;
      case 'consolidate_users':
        /* merge two users into one */
        if (!(current_user_can('delete_users') || !function_exists('wpmu_delete_user'))) {
          $this->display_updated('Sorry, you do not have access to user consolidation.');
          break;
        }
        $user1=$_REQUEST['user1'];
        $user2=$_REQUEST['user2'];
        if (!$user1 || !$user2 || $user1==$user2 || $user2==1) {
          $this->display_updated('Two unique users must be selected for consolidation.');
          break;
        }
        # Validate WPMU operation, user1 must be able to receive posts from user2.
        if (function_exists('wpmu_delete_user')) {
          # Which blogs does user2 belong to?
          $blogs=get_blogs_of_user($user2);
          if (!sizeof($blogs)) {
            $this->display_updated('User 2 does not have any blogs, unable to consolidate');
            break;
          }
          # Make sure user1 belongs to the same blogs.
          $ok=true;
          foreach ($blogs as $blog => $info) {
            if (!is_user_member_of_blog($user1, $blog)) {
              $this->display_updated('User 1 does not belong to blog '.$blog.', unable to consolidate');
              $ok=false;
            }
          }
          if (!$ok)
            break;
        }
        # Move Venus ID(s) for user2 to user1.
        $wpdb->query('UPDATE ' . $wpdb->usermeta . ' SET user_id="' . $wpdb->escape($user1) . '" WHERE meta_key="venus_id" AND user_id="' . $wpdb->escape($user2) . '"');
        # Delete user.
        if (function_exists('wpmu_delete_user')) {
          # WPMU: Remove user2 after moving posts to user1 for each blog.
          foreach ($blogs as $blog => $info) {
            if ($this->debug)
              $this->log('removing user #'.$user2.' from blog #'.$blog);
            switch_to_blog($blog);
            wp_delete_user($user2, $user1);
            restore_current_blog();
          }
          wpmu_delete_user($user2);
        } else {
          # WP: Remove user2, moving posts to user1.
          wp_delete_user($user2, $user1);
        }
         if ($this->debug)
          $this->log('consolidated user #'.$user2.' into user #'.$user1);
        $this->display_updated('Users merged.');
        break;
    }
    if (function_exists('wpmu_delete_user'))
      restore_current_blog();
  }
  
  function options_venus_display() {
    /* Display options page */
    global $wpdb, $wp_roles;
    if (!current_user_can('edit_plugins') || function_exists('is_site_admin') && !is_site_admin())
      return;
    $options = get_settings('venus_options');
    ?>
    <div class="wrap">
      <h2><?php $this->EHT('Venus Options') ?></h2>
      <?php
        if ($this->debug) {
          print '<p>Debug is enabled, <a href="/wp-content/venus.log">view log</a>.</p>';
        }
      ?>
      <form method="post" action="">
        <fieldset class="options">
          <input type="hidden" name="action" value="do_update" />
          <div class="submit"><input type="submit" value="<?php
                                   echo $this->EHT('Force update...') ?> &raquo;" /></div>
        </fieldset>
      </form>
      <form method="post" action="">
        <input type="hidden" name="action" value="update_options" />
        <fieldset class="options">
        <legend><?php $this->EHT('General options') ?></legend>
        <table class="editform">
          <tr>
            <td><?php echo $this->EHT("Absolute path to Venus cache directory").": " ?></td>
            <td><input name="cache_directory" value="<?php echo $this->H($options['cache_directory']) ?>"
                       type="text" size="40" /></td>
          </tr><tr>
            <td><?php echo $this->EHT("Default role for new users").": " ?></td>
            <td><select name="default_user_role"><?php 
              foreach ($wp_roles->role_names as $role => $name)
                echo '<option value="'.$role.'" '.($options['default_user_role']==$role?' selected="selected"':'').'>'.$name.'</option>';
            ?></select></td>
          </tr><tr>
            <td><?php echo $this->EHT("Minimum update interval (minutes)").": " ?></td>
            <td><input name="update_interval" value="<?php echo $this->H($options['update_interval']) ?>"
                       title="<?php echo strftime('%a, %d %b %Y %H:%M:%S', $options['last_update']); ?>" type="text" size="5" /></td>
          </tr><tr>
            <td><?php echo $this->EHT("Tag with source URL?").": " ?></td>
            <td><input name="tag_with_source" value="1"
                       type="checkbox" <?php if (1==$options['tag_with_source']) echo 'checked="true" '; ?>/></td>
          </tr><tr>
            <td><?php echo $this->EHT("Check entry size?").": " ?></td>
            <td><input name="check_entry_size" value="1"
                       type="checkbox" <?php if (1==$options['check_entry_size']) echo 'checked="true" '; ?>/></td>
          </tr><tr>
            <td><?php echo $this->EHT("Use original link to post?").": " ?></td>
            <td><input name="original_link" value="1"
                       type="checkbox" <?php if (1==$options['original_link']) echo 'checked="true" '; ?>/></td>
          </tr>
        </table>
        <div class="submit"><input type="submit" value="<?php
                                   echo $this->EHT('Update options') ?> &raquo;" /></div>
        </fieldset>
      </form>
      <?php
        $users=$wpdb->get_results('SELECT u.ID, display_name, replace(user_url, "http://", "") as user_url, user_email, count(*) as post_count FROM '.$wpdb->users.' AS u LEFT JOIN '.$wpdb->posts.' AS p ON u.ID=p.post_author WHERE u.ID>1 GROUP BY u.ID ORDER BY display_name');
        if (sizeof($users)<=1)
          print '<!-- no venus users found -->';
        if ((sizeof($users)>1) && (current_user_can('delete_users') || !function_exists('wpmu_delete_user'))) {
      ?>
      <form method="post" action="">
        <input type="hidden" name="action" value="consolidate_users" />
        <fieldset class="options">
        <legend><?php $this->EHT('Consolidate users (merge User 2 into User 1)') ?></legend>
        <table class="editform">
          <tr>
            <th style="text-align: left"><?php echo $this->EHT("User 1").": " ?></th>
          </tr><tr>
            <td>
              <select name="user1">
                <option value="0"><?php echo $this->EHT("Select...") ?></option>
                <?php
                  foreach ($users as $user)
                    print '<option value="'.$user->ID.'">'.$this->H($user->display_name).($user->user_email!=''?', '.$this->H($user->user_email):'').' (ID: '.$this->H($user->ID).', posts: '.$this->H($user->post_count).', '.$this->H($user->user_url).')</option>';
                ?>

              </select>
            </td>
          </tr><tr>
            <th style="text-align: left"><?php echo $this->EHT("User 2").": " ?></th>
          </tr><tr>
            <td>
              <select name="user2">
                <option value="0"><?php echo $this->EHT("Select...") ?></option>
                <?php
                  foreach ($users as $user)
                    print '<option value="'.$user->ID.'">'.$this->H($user->display_name).($user->user_email!=''?', '.$this->H($user->user_email):'').' (ID: '.$this->H($user->ID).', posts: '.$this->H($user->post_count).', '.$this->H($user->user_url).')</option>';
                ?>

              </select>
            </td>
          </tr>
        </table>
        <div class="submit"><input type="submit" value="<?php
                                   echo $this->EHT('Consolidate') ?> &raquo;" /></div>
        </fieldset>
      </form>
      <?php
        }
      ?>
    </div>
    <?
  }

  function display_updated($text) {
    echo '<div class="updated"><p>';
    $this->EHT($text);
    echo '</p></div>';
  }

  function T($text) {
    return __($text, 'venus');
  }

  function H($text) {
    return htmlspecialchars($text, ENT_QUOTES);
  }

  function HT($text) {
    return $this->H($this->T($text));
  }

  function EHT($text) {
    echo $this->HT($text);
  }

  function update($force=false) {
    global $wpdb;
    
    $options = get_settings('venus_options');
    # Not yet time to check for updates?
    if (!$force && (($options['last_update'] + $options['update_interval'] * 60) > mktime()))
      return;

    $options['last_update'] = mktime();
    update_option('venus_options', $options);
    if ($this->debug)
      $this->log('ready to update.');
    # Loop through files in cache directory.
    $handle = @opendir($options['cache_directory']);
    if (!$handle)
      return;
    if ($this->debug)
      $this->log('reading directory...');
    $entries = 0;
    while (($filename = @readdir($handle)) !== false) {
      $path = $options['cache_directory'] . DIRECTORY_SEPARATOR . $filename;
      # Only handle real files.
      if (@is_dir($path))
        continue;

      # Check for existing entry/post.
      $filemtime = @filemtime($path);
      $filesize = @filesize($path);
      $post = $wpdb->get_row('select ID, pm2.meta_value as mtime, pm3.meta_value as size from ' . $wpdb->posts .
                             ' join  ' . $wpdb->postmeta . ' as pm1 ' .
                             ' join  ' . $wpdb->postmeta . ' as pm2 ' .
                             ' join  ' . $wpdb->postmeta . ' as pm3 ' .
                             ' where ID = pm1.post_id and ID = pm2.post_id and ID = pm3.post_id ' .
                             ' and pm1.meta_key = "venus_cache_file" and pm1.meta_value = "' . $filename . '" ' .
                             ' and pm2.meta_key = "venus_cache_mtime"' .
                             ' and pm3.meta_key = "venus_cache_size" limit 1');
      # Unchanged entry/post?
      if ($post && $filemtime == $post->mtime && ($filesize == $post->size || !$options['check_entry_size']))
        continue;
      if ($this->debug) {
        if ($post)
          $this->log('updated entry #'.$post->ID.' ('.$filemtime.'/'.$post->mtime.'/'.$filesize.'/'.$post->size.'): '.$filename);
        else
          $this->log('new entry ('.$filemtime.'/'.$filesize.'): '.$filename);
      }

      # Parse entry.
      $this->parse_path($path);
      if ('FEED'==$this->parse_tree[0]['name'] && isset($this->parse_tree[0]['nodes']['entry'][0])) {
        foreach ($this->parse_tree[0]['nodes']['entry'] as $entry) {
          if (!isset($entry['source'])) {
            $entry['source'] = $this->parse_tree[0]['nodes'];
            unset($entry['source']['entry']);
          }
          $entries += $this->insert_entry($post, $entry, $filename, $filemtime, $filesize);
        }
      } elseif ('ENTRY'==$this->parse_tree[0]['name']) {
        $entry = $this->parse_tree[0]['nodes'];
        $entries += $this->insert_entry($post, $entry, $filename, $filemtime, $filesize);
      }
    }
    if ($this->debug)
      $this->log('done, found '.$entries.' new entries.');
    return $entries;
  }

  function parse_path($path) {
    $xml = file_get_contents($path);
    if (!function_exists('xml_parser_create')
        || !($parser = @xml_parser_create('UTF-8'))
        || !is_resource($parser))
      trigger_error('Unable to create XML/Atom parser');
    xml_set_element_handler($parser,
                            array(&$this, 'entry_start_element'),
                            array(&$this, 'entry_end_element'));
    xml_set_character_data_handler($parser, array(&$this, 'entry_cdata')); 
    $this->parse_tree = array();
    $this->parse_level = 0;
    $this->parse_inxhtml = false;
    if (xml_parse($parser, $xml, true) && 
        ($errorcode = xml_get_error_code($parser)) != XML_ERROR_NONE)
      trigger_error('Unable to parse Atom entry (' .
                    sprintf(__('XML error: %1$s at line %2$s'),
                    xml_error_string($errorcode),
                    xml_get_current_line_number($parser)) . ')');
    xml_parser_free($parser);
  }

  function insert_entry($post, $entry, $filename, $filemtime, $filesize) {
    global $wpdb;
    $options = get_settings('venus_options');

    if (!isset($entry['author']) && isset($entry['source']['author']))
      $entry['author'] = &$entry['source']['author'];
    if (!isset($entry['category']) && isset($entry['source']['category']))
      $entry['category'] = &$entry['source']['category'];
    if (!isset($entry['author']['uri']) && isset($entry['source']['id']))
      $entry['author']['uri'] = &$entry['source']['id'];
    elseif (!isset($entry['author']['uri']) && isset($entry['source']['link_alternate']))
      $entry['author']['uri'] = &$entry['source']['link_alternate'];
    elseif (!isset($entry['author']['uri']) && isset($entry['source']['link_self']))
      $entry['author']['uri'] = &$entry['source']['link_self'];
    $entry['summary']=preg_replace('|\[i\](.+?)\[/i\]|','<em>$1</em>',$entry['summary']);
    $entry['summary']=preg_replace('|\[b\](.+?)\[/b\]|','<strong>$1</strong>',$entry['summary']);
    $entry['summary']=preg_replace('|\s+---\s+|',' &mdash; ',$entry['summary']);
    if (!isset($entry['content']))
      $entry['content'] = $entry['summary'];
    $entry['summary']=strip_tags($entry['summary']);

    # Find author.
    $where = array();
    if (isset($entry['author']['uri']) && !empty($entry['author']['uri']))
      $where[] = 'user_url = "' . $wpdb->escape($entry['author']['uri']) . '"';
    if (isset($entry['author']['email']) && !empty($entry['author']['email']))
      $where[] = 'user_email = "' . $wpdb->escape($entry['author']['email']) . '"';
    if (isset($entry['author']['name']) && !empty($entry['author']['name']) && 'admin'==$entry['author']['name'])
      $entry['author']['name'] .= md5($entry['author']['uri']);
    if (isset($entry['author']['name']) && !empty($entry['author']['name']))
      $where[] = 'display_name = "' . $wpdb->escape($entry['author']['name']) . '"';
    if (!sizeof($where))
      $post->post_author = 0;
    else {
      $query = 'SELECT ID FROM ' . $wpdb->users . ' WHERE ' . join(' AND ', $where) . ' ORDER BY ID LIMIT 1';
      $post->post_author = $wpdb->get_var($query);
      $venus_id = $entry['author']['uri'].':'.$entry['author']['email'].':'.$entry['author']['name'];
      if (!$post->post_author) {
        $query = 'SELECT user_id FROM ' . $wpdb->usermeta . ' WHERE meta_key="venus_id" AND meta_value="' . $wpdb->escape($venus_id) . '" ORDER BY user_id LIMIT 1';
        $post->post_author = $wpdb->get_var($query);
      }
      if (!$post->post_author) {
        # Create author.
        include_once(ABSPATH . WPINC . '/registration-functions.php');
        $author = array();
        if (isset($entry['author']['name']) && !empty($entry['author']['name']))
          $author['user_login'] = $entry['author']['name'];
        elseif (isset($entry['author']['email']) && !empty($entry['author']['email']))
          $author['user_login'] = preg_replace('|@.+$|','',$entry['author']['email']);
        elseif (isset($entry['author']['uri']) && !empty($entry['author']['uri']))
          $author['user_login'] = 'u'.md5($entry['author']['uri']);
        if (isset($entry['author']['email']) && !empty($entry['author']['email']))
          $author['user_email'] = $entry['author']['email'];
        if (isset($entry['author']['uri']) && !empty($entry['author']['uri']))
          $author['user_url'] = $entry['author']['uri'];
        $author['user_nicename'] = $author['user_login'];
        $author['display_name'] = $author['user_login'];
        $author['nickname'] = $author['user_login'];
        $author['user_login'] = sanitize_title(sanitize_user($this->remove_accents($author['user_login']), true));
        $author['user_nicename'] = $author['user_login'];
        $author['user_pass'] = 'p'.md5(mktime());
        $post->post_author = wp_insert_user($author);
        $user = new WP_User($post->post_author);
        $user->set_role($options['default_user_role']);
        update_usermeta($post->post_author, 'venus_id', $wpdb->escape($venus_id));
        if ($this->debug)
          $this->log('created author #'.$post->post_author.': '.$author['user_nicename']);
      }
    }

    # Find categories.
    $post->post_category = array();
    if (isset($entry['category']) && is_array($entry['category'])) {
      if (isset($entry['category']['term']))
        $entry['category']=array($entry['category']);
      $categories = array();
      foreach ($entry['category'] as $c) {
        if (is_array($c) && isset($c['term']))
          $c = $c['term'];
        elseif (is_array($c) && isset($c[0]) && isset($c[0]['term'])) {
          $cc = array();
          foreach ($c as $ct)
            $cc[] = $ct['term'];
          $c = join(',', $cc);
        }
        $c = preg_split('/\s*,+\s*/', $c, -1, PREG_SPLIT_NO_EMPTY);
        $categories = array_merge($categories, $c);
      }
      if ($this->debug)
        $this->log('categories to insert: '.join(', ', $categories));
      if (!function_exists('wp_insert_category') || !function_exists('category_exists')) {
        if (file_exists(ABSPATH . 'wp-admin/includes/admin.php')) {
          if ($this->debug)
            $this->log('using wp-admin/includes/admin.php');
          require_once(ABSPATH . 'wp-admin/includes/admin.php');
        } elseif (file_exists(ABSPATH . 'wp-admin/admin-db.php')) {
          if ($this->debug)
            $this->log('using wp-admin/admin-db.php');
          include_once(ABSPATH . 'wp-admin/admin-db.php');
        } else {
          if ($this->debug)
            $this->log('unable to create categories...');
          break;
        }
      }
      foreach ($categories as $category) {
        if (strlen($category)<2)
          continue;
        $cat_nicename = sanitize_title($category);
        $cat_nicename = apply_filters('pre_category_nicename', $cat_nicename);
        if (function_exists('category_exists')) {
          $cat = category_exists($category);
          if ($this->debug)
            $this->log('category check: '.$cat_nicename.', '.$category.($cat?' (#'.$cat.')':''));
        } else {
          $cat = $wpdb->get_var('SELECT cat_ID FROM ' . $wpdb->categories . ' WHERE category_nicename = "' . $wpdb->escape($cat_nicename) . '" OR cat_name = "' . $wpdb->escape($category) . ' " LIMIT 1');
          if ($this->debug)
            $this->log('using category: '.$cat_nicename.', '.$category.($cat?' (#'.$cat.')':''));
        }
        if (!$cat) {
          # Create category.
          $cat = wp_insert_category(array(
            'cat_name' => $wpdb->escape($category),
            'category_nicename' => $wpdb->escape($category)));
          if ($this->debug)
            $this->log('created category #'.$cat.': '.$cat_nicename.', '.$category);
        }
        $post->post_category[] = $cat;
      }
    }
     
    # Create or update post
    include_once(ABSPATH . WPINC . '/rss-functions.php');
    $post->post_content = $wpdb->escape($entry['content']);
    $post->post_excerpt = $wpdb->escape($entry['summary']);
    $post->post_title = $wpdb->escape($entry['title']);
    $post->post_status = 'publish';
    $post->post_date = date('Y-m-d H:i:s',parse_w3cdtf($entry['updated']));
    $post->comment_status = 'closed';
    $post->ping_status = 'closed';      
    $post->post_pingback = 0;
    if ($options['tag_with_source'] && isset($entry['source']['link_alternate'])) {
      $post->tags_input = $entry['source']['link_alternate'];
      if ($this->debug)
        $this->log('tagged post with "'.$post->tags_input.'"');
    }
    if (!isset($entry['link_alternate']))
      $this->permalink=$entry['id'];
    else
      $this->permalink=$entry['link_alternate'];
    define('WP_IMPORTING', 1);
    $post_id = wp_insert_post($post);
    if ($this->debug)
      $this->log('created post #'.$post_id);
    if ($post_id && !$post->ID) {
      add_post_meta($post_id, 'venus_cache_file', $filename);
      add_post_meta($post_id, 'venus_cache_mtime', $filemtime);
      add_post_meta($post_id, 'venus_cache_size', $filesize);
      return 1;
    } elseif ($post_id) {
      update_post_meta($post_id, 'venus_cache_mtime', $filemtime);
      update_post_meta($post_id, 'venus_cache_size', $filesize);
      return 0;
    }
  }

  function entry_start_element($parser, $elem, &$attrs) {
    $attrs = array_change_key_case($attrs, CASE_LOWER);
    $this->parse_level++;
    $node = &$this->parse_tree;
    $level = $this->parse_level - 1;
    while ($level) {
      $node = &$node[sizeof($node)-1]['nodes'];
      $level--;
    }
    if ($this->parse_inxhtml) {
      $e = '<' . strtolower($elem);
      foreach ($attrs as $a => $v)
        $e .= ' ' . $a . '="' . htmlspecialchars($v) . '"';
      $e .= '>'; 
      $this->parse_xhtml .= $e;
    } elseif (isset($attrs['xmlns']) && $attrs['xmlns'] == 'http://www.w3.org/1999/xhtml') {
      $this->parse_inxhtml = $this->parse_level-1;
      $e = '<' . strtolower($elem);
      foreach ($attrs as $a => $v)
        $e .= ' ' . $a . '="' . htmlspecialchars($v) . '"';
      $e .= '>'; 
      $this->parse_xhtml = $e;
    }
    if ('LINK'==$elem && isset($attrs['rel'])) {
      $elem .= '_' . $attrs['rel'];
      $node[] = array('name' => $elem, 'text' => $attrs['href']);
    } else 
      $node[] = array('name' => $elem, 'attrs' => $attrs);
  }
  
  function entry_end_element($parser, $elem) {
    $this->parse_level--;
    $node = &$this->parse_tree;
    $level = $this->parse_level;
    while ($level) {
      $node = &$node[sizeof($node)-1]['nodes'];
      $level--;
    }
    if ($this->parse_inxhtml) {
      $this->parse_xhtml .= '</' . strtolower($elem) . '>';
      if ($this->parse_inxhtml == $this->parse_level) {
        $this->parse_inxhtml = false;
        $node = $this->parse_xhtml;
      }
    }
    if (isset($node[sizeof($node)-1]['attrs']) && !sizeof($node[sizeof($node)-1]['attrs']))
      unset($node[sizeof($node)-1]['attrs']);
    if (isset($node[sizeof($node)-1]['nodes']) && !sizeof($node[sizeof($node)-1]['nodes']))
      array_pop($node);
    elseif (isset($node[sizeof($node)-1]['nodes']) && is_array($node[sizeof($node)-1]['nodes'])) {
      $nodes = array();
      foreach ($node[sizeof($node)-1]['nodes'] as $n) {
        if (isset($n['nodes']))
          $v = $n['nodes'];
        elseif (isset($n['text']))
          $v = $n['text'];
        else
          $v = $n['attrs'];
        if (isset($nodes[$n['name']])) {
          if (isset($nodes[$n['name']][0])) {
            if (is_array($nodes[$n['name']][0]))
              $nodes[$n['name']][] = $v;
            elseif (!is_array($v))
              $nodes[$n['name']] .= $v;
          } else
            $nodes[$n['name']] = array($nodes[$n['name']], $v);
        } else
          $nodes[$n['name']] = $v;
      }
      if (sizeof($nodes))
        $node[sizeof($node)-1]['nodes'] = array_change_key_case($nodes, CASE_LOWER);
    }
  }

  function entry_cdata($parser, $text) {
    $node = &$this->parse_tree;
    $level = $this->parse_level - 1;
    while ($level) {
      $node = &$node[sizeof($node)-1]['nodes'];
      $level--;
    }
    if ($this->parse_inxhtml)
      $this->parse_xhtml .= $text;
    else {
      if (!isset($node[sizeof($node)-1]['text']))
        $node[sizeof($node)-1]['text']='';
      $node[sizeof($node)-1]['text'] .= $text;
    }
  }
  
  function remove_accents($s) {
    if (seems_utf8($s)) {
      $chars = array(
        chr(195).chr(134) => 'AE',  # Aelig
        chr(195).chr(166) => 'ae',  # aelig
        chr(195).chr(184) => 'oe',  # oslash
        chr(195).chr(152) => 'OE',  # Oslash
        chr(195).chr(133) => 'AA',  # Aring
        chr(195).chr(165) => 'aa'  # aring
      );
      $s = strtr($s, $chars);
    }
    return remove_accents($s);  
  }

  function action_init() {
    load_plugin_textdomain('venus');
  }

  function action_publish_post($post_id) {
    add_post_meta($post_id, 'venus_original_link', htmlspecialchars($this->permalink));
  }
  
  function filter_post_link($permalink = '') {
    $options = get_settings('venus_options');
    if ($options['original_link']) {
      list($uri) = get_post_custom_values('venus_original_link');
      return ((strlen($uri) > 0) ? $uri : $permalink);
    } else
      return $permalink;
  }

  function filter_get_the_guid($permalink = '') {
    return $this->filter_post_link($permalink);
  }

  function show_user_profile() {
      global $wpdb, $user_ID;
      if (!current_user_can('edit_plugins') || function_exists('is_site_admin') && !is_site_admin())
        return;
      if (isset($_REQUEST['user_id']))
          $user_ID = $_REQUEST['user_id'];
      $vids = $wpdb->get_col('SELECT meta_value FROM '.$wpdb->usermeta.' WHERE meta_key = "venus_id" AND user_id = '.$wpdb->escape($user_ID));
      if (!sizeof($vids))
        return;
      ?>
  <fieldset style="width: 89%">
      <legend><?php _e('Venus ID List', 'venus'); ?></legend>
      <table>
        <?php
      foreach ($vids as $vid)
        print '<tr><td><input type="checkbox" checked="checked" name="venus_id[]" id="venus_id_'.md5($vid).'" value="'.$vid.'"/></td><td><code><label for="venus_id_'.md5($vid).'">'.$vid.'</label></code></td></tr>';
        ?>
      </table>
  </fieldset>
      <?
  }

  function check_passwords() {
    global $wpdb, $current_user;
    if (isset($_POST['user_id']))
      $id=$_POST['user_id'];
    elseif (isset($_POST['checkuser_id']))
      $id=$_POST['checkuser_id'];
    else
      return;
    if (!$current_user->has_cap('edit_users')
        && !$current_user->has_cap('administrator')
        || $id==1 && $current_user->ID!=1)
      return;
    $vids = $wpdb->get_col('SELECT meta_value FROM '.$wpdb->usermeta.' WHERE meta_key = "venus_id" AND user_id = '.$wpdb->escape($id));
    $newvids = $_POST['venus_id'];
    foreach ($vids as $vid) {
      if (!in_array($vid, $newvids))
        delete_usermeta($id, 'venus_id', $vid);
    }
  }

  function log($line) {
    $fh = @fopen(ABSPATH . "wp-content/venus.log", "a");
    @fwrite($fh, strftime("%D %T")."\t$line\n");
    @fclose($fh);
  }

}

# Create global Venus object.
$venus = get_venus();

# Include configuration if called directly.
if (!function_exists('add_action')) {
  $venus->do_update=true;
  if (file_exists('../../wp-config.php'))
    include_once('../../wp-config.php');
  elseif (file_exists('../../../wp-config.php'))
    include_once('../../../wp-config.php');
  else {
    $venus->do_update=false;
  }
}

if (function_exists('add_action')) {
  add_option('venus_options', array(
      'last_update' => 0,
      'original_link' => 0,
      'check_entry_size' => 0,
      'update_interval' => 55,
      'default_user_role' => 'author',
      'tag_with_source' => 0,
      'cache_directory' => ''));

  add_action('publish_post', array(&$venus, 'action_publish_post'), 1);

  if ($venus->do_update)
    $venus->update();

  add_action('init', array(&$venus, 'action_init'));
  add_action('admin_menu', array(&$venus, 'action_admin_menu'));
  add_action('delete_post', array(&$venus, 'action_delete_post'));
  add_filter('post_link', array(&$venus, 'filter_post_link'), 1);
  add_filter('get_the_guid', array(&$venus, 'filter_get_the_guid'), 1);
  add_action('show_user_profile', array(&$venus, 'show_user_profile'));
  add_action('edit_user_profile', array(&$venus, 'show_user_profile'));
  add_action('check_passwords', array(&$venus, 'check_passwords'));
#  add_action('wp_head', array(&$venus, 'update'));
}

?>
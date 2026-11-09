from sub_convert import sub_convert
from subs_function import subs_function

import json
import re
import os
import yaml
import ipaddress

sub_list_json = './sub/sub_list.json'
sub_merge_path = './sub/'
sub_list_path = './sub/list/'

ipv4 = r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
ipv6 = r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
ill = ['|', '?', '[', ']', '@', '!', '%', ':']
valid_ss_cipher_methods = ["aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "rc4-md5", "chacha20-ietf", "xchacha20", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"]
valid_ss_plugins = ["obfs","v2ray-plugin"]

class subs:

    @staticmethod

    def filter_non_local(items):
        """
        Remove entries whose c_clash.server IP is:
        - private
        - loopback (127.x.x.x)
        - link-local
        - reserved
        - multicast
        - unspecified (0.0.0.0)
        - invalid addresses
        """
        filtered = []
    
        for item in items:
            server_ip = item.get("c_clash", {}).get("server")
    
            try:
                ip_obj = ipaddress.ip_address(server_ip)
    
                # Remove all non-public or invalid types
                if (
                    ip_obj.is_private or
                    ip_obj.is_loopback or
                    ip_obj.is_link_local or
                    ip_obj.is_reserved or
                    ip_obj.is_multicast or
                    ip_obj.is_unspecified     # catches 0.0.0.0
                ):
                    continue
    
            except ValueError:
                # skip invalid IPs (e.g. empty, None, text)
                continue
    
            filtered.append(item)
    
        return filtered

    def get_subs_v3(content_urls: [], output_path="sub_merge_yaml", should_cleanup=True, specific_files_cleanup=["1105.txt"]):
        if content_urls == []:
            return

        if should_cleanup:
            for t in os.walk(sub_list_path):
                for f in t[2]:
                    if specific_files_cleanup.__contains__(f) == False:
                        f = t[0]+f
                        os.remove(f)
        else:
            for t in os.walk(sub_list_path):
                for f in t[2]:
                    if specific_files_cleanup.__contains__(f):
                        f = t[0]+f
                        os.remove(f)

        content_list = []
        corresponding_list = []
        corresponding_id = 0
        bad_lines = 0
        for (index, url_container) in enumerate(content_urls):
            ids = content_urls[index]['id']
            remarks = content_urls[index]['remarks']
            if type(url_container['url']) == list:
                for each_url in url_container["url"]:
                    print("gather server from " + each_url)

                    # todo change to 0.0.0.0
                    # getting one source in to format
                    content_clash = subs_function.convert_sub(
                        each_url, 'clash', "http://0.0.0.0:25500", False, extra_options="&udp=false")

                    if content_clash == 'Err: No nodes found' or content_clash == 'Err: failed to parse sub':
                        if content_clash == 'Err: No nodes found':
                            print(
                                "host convertor was unable to find any nodes. just continue & ignore...\n")
                            # file = open(f'{sub_list_path}{ids:0>2d}.txt',
                            #             'a+', encoding='utf-8')
                            # file.write('Err: No nodes found')
                            # file.close()

                        if content_clash == 'Err: failed to parse sub':
                            print(
                                "host convertor failed. just continue & ignore...\n")
                            # file = open(f'{sub_list_path}{ids:0>2d}.txt',
                            #             'a+', encoding='utf-8')
                            # file.write('Err: failed to parse sub')
                            # file.close()

                    elif content_clash != None and content_clash != '':
                        single_url_gather_quantity = list(
                            filter(lambda x: x != '', content_clash.split('\n'))).__len__()
                        print(
                            f"added content of current url : {single_url_gather_quantity - 1}")

                        # Convert both format to list
                        clash_content = list(
                            filter(lambda x: x != '', content_clash.split('\n')[1:]))

                        # check of the size of lists are equal
                        if clash_content.__len__() > 0:
                            # create a new list for clash lines check result
                            safe_clash = []
                            # check for bad line in clash content (yaml check)
                            for (index, cl) in enumerate(clash_content):
                                try:
                                    if re.search(ipv6, str(cl)) == None or re.search(ipv4, str(cl)) != None:
                                        if re.search("path: /(.*?)\?(.*?)=(.*?)}", str(cl)) == None:
                                            # todo first trying without it
                                            # # fix name issues and replacing the illegal character with empty string
                                            # try:
                                            #     if 'name' in cl:
                                            #         match_re = re.search(
                                            #             "name: (.*?),", cl)[1]
                                            #         if match_re != None:
                                            #             match_re = match_re.replace(":", "").replace(
                                            #                 "|", "").replace('\'', '').replace('"', '')
                                            #             for char in ill:
                                            #                 match_re = match_re.replace(
                                            #                     char, "")
                                            #             cl = re.sub(
                                            #                 "name: (.*?),", f"name: {match_re},", cl)
                                            # except:
                                            #     pass
                                            cl_res = yaml.safe_load(cl)
                                            if cl_res != None:
                                                # safe_clash.append(cl)
                                                # it's not text it's yaml object
                                                try:
                                                    cl_temp = yaml.safe_load(
                                                        str(cl_res[0]))
                                                    if cl_temp != None:
                                                        bad_uuid_format = False
                                                        if 'uuid' in cl_temp:
                                                            if cl_temp['uuid'].__len__() != 36:
                                                                bad_uuid_format = True
                                                                bad_lines += 1
                                                        
                                                        if bad_uuid_format == False:
                                                            if cl_temp['type'] == "ss" or cl_temp['type'] == "ssr":
                                                                if cl_temp["cipher"] in valid_ss_cipher_methods:
                                                                    if cl_temp['type'] == "ss":
                                                                        if 'plugin' in cl_temp:
                                                                            if cl_temp['plugin'] in valid_ss_plugins:
                                                                                
                                                                                if cl_temp['plugin'] == 'obfs':
                                                                                    if 'plugin-opts' in cl_temp:
                                                                                        if cl_temp['plugin-opts']['mode'] == 'http' or cl_temp['plugin-opts']['mode'] == 'tls':
                                                                                            safe_clash.append(cl_res)
                                                                                        else:
                                                                                            bad_lines += 1
                                                                                    else:
                                                                                        safe_clash.append(cl_res)
                                                                                elif cl_temp['plugin'] == 'v2ray-plugin':
                                                                                    if 'plugin-opts' in cl_temp:
                                                                                        if cl_temp['plugin-opts']['mode'] == 'websocket':
                                                                                            safe_clash.append(cl_res)
                                                                                        else:
                                                                                            bad_lines += 1
                                                                                    else:
                                                                                        safe_clash.append(cl_res)
                                                                                else:
                                                                                    safe_clash.append(cl_res)
                                                                                    
                                                                            else:
                                                                                bad_lines += 1
                                                                        else:
                                                                            safe_clash.append(cl_res)
                                                                    else:
                                                                        safe_clash.append(cl_res)
                                                                else:
                                                                    bad_lines += 1

                                                            elif cl_temp['type'] == "vmess":
                                                                if cl_temp["network"] == "h2" or cl_temp["network"] == "grpc":
                                                                    if "tls" in cl_temp and cl_temp['tls'] == False:
                                                                        bad_lines += 1
                                                                    else:
                                                                        safe_clash.append(cl_res)
                                                                        
                                                                else:
                                                                    safe_clash.append(cl_res)

                                                            else:
                                                                safe_clash.append(cl_res)
                                                            
                                                except Exception as e1:
                                                    bad_lines += 1

                                except Exception as e:
                                    bad_lines += 1
                                    # if fails remove the same index from both lists
                                    # clash_content.pop(index)
                                    # mixed_content.pop(index)

                            if safe_clash.__len__() > 0:
                                content_list.append(
                                    "\n".join(clash_content) + "\n")
                                file = open(f'{sub_list_path}{ids:0>2d}.txt',
                                            'a+', encoding='utf-8')
                                file.write("\n".join(clash_content) + "\n")
                                file.close()
                                print(
                                    f'Writing content of {remarks} to {ids:0>2d}.txt\n')

                                print("Check Points Passed 👍\n")
                                for (i, each_clash_proxy) in enumerate(safe_clash):
                                    # c_clash type is a list with one item
                                    corresponding_list.append(
                                        {"id": corresponding_id, "c_clash": each_clash_proxy})
                                    corresponding_id += 1

                            else:
                                print(
                                    f'there is no clash lines {each_url}')
                                # file = open(f'{sub_list_path}{ids:0>2d}.txt',
                                #             'a+', encoding='utf-8')
                                # file.write("there is no clash lines")
                                # file.close()
                                print(
                                    f'Writing content of {remarks} to {ids:0>2d}.txt\n')

                        else:
                            print(
                                f'there is no clash lines first stage {each_url}')
                            # file = open(f'{sub_list_path}{ids:0>2d}.txt',
                            #             'a+', encoding='utf-8')
                            # file.write(
                            #     "there is no clash lines first stage")
                            # file.close()
                            print(
                                f'Writing content of {remarks} to {ids:0>2d}.txt\n')

                    else:
                        # file = open(f'{sub_list_path}{ids:0>2d}.txt',
                        #             'a+', encoding='utf-8')
                        # file.write('Url Subscription could not be parsed')
                        # file.close()
                        print(
                            f'Writing error of {remarks} to {ids:0>2d}.txt\n')

            gather_quantity = list(
                filter(lambda x: x != '', ''.join(content_list).split('\n'))).__len__()
            print(f"already gathered {gather_quantity}")

            print('\n')
            print('----------------------------------------------')
            print('\n')

        print('Merging nodes...\n')

        content_list = list(
            filter(lambda x: x != '', ''.join(content_list).split("\n")))
        content_raw = "\n".join(content_list)

        print(f"{content_list.__len__()} lines - {bad_lines} bad lines => total is {content_list.__len__() - bad_lines}")

        ################ everything is fine till here ################
        '''
        we should have a list of corresponding proxies and they are ready to be fixed in 2 steps:
        1- making their name better (using their server) => via thier clash corresponding
        2- remove duplicate proxies from the list => via thier clash corresponding
        after that we have clean list that contains both type that we need, with modification and no conversion :)
        '''

        ################  Fix names  ################
        corresponding_list = subs_function.fix_proxies_name(
            corresponding_proxies=corresponding_list)

        ################  Fix Duplication  ################
        corresponding_list = subs_function.fix_proxies_duplication(
            corresponding_proxies=corresponding_list)

        print(f"\n before validation sub length => {corresponding_list.__len__()}")
        corresponding_list = (subs.filter_non_local(corresponding_list))
        
        print(f"\nfinal sub length => {corresponding_list.__len__()}")
        # print(f"\nfinal sub content => {corresponding_list}")


        clash = list(map(lambda x: f"  - {x['c_clash']}", corresponding_list))
        content_yaml = 'proxies:\n' + "\n".join(clash)

        # mixed = list(map(lambda x: x["c_mixed"], corresponding_list))
        # content_raw = "\n".join(mixed)
        # content_base64 = sub_convert.base64_encode(content_raw)
        # content = content_raw

        ##############################

        def content_write(file, output_type):
            file = open(file, 'w+', encoding='utf-8')
            file.write(output_type)
            file.close

        content_write(f'{sub_merge_path}/{output_path}.yml', content_yaml)
        print('Done!\n')


if __name__ == "__main__":
    subs.get_subs([])

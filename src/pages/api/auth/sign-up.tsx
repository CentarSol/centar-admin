/* eslint-disable */
/*!
	_   _  ___  ____  ___ ________  _   _   _   _ ___   
 | | | |/ _ \|  _ \|_ _|__  / _ \| \ | | | | | |_ _| 
 | |_| | | | | |_) || |  / / | | |  \| | | | | || | 
 |  _  | |_| |  _ < | | / /| |_| | |\  | | |_| || |
 |_| |_|\___/|_| \_\___/____\___/|_| \_|  \___/|___|
																																																																																																																																																																			 
=========================================================
* Horizon UI - v1.1.0
=========================================================

* Product Page: https://www.horizon-ui.com/
* Copyright 2022 Horizon UI (https://www.horizon-ui.com/)

* Designed and Coded by Simmmple
 
=========================================================

* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

*/

import React, { useEffect, useState } from 'react';
// Chakra imports
import {
	Box,
	Button,
	Checkbox,
	Flex,
	FormControl,
	FormLabel,
	Heading,
	Icon,
	Input,
	InputGroup,
	InputRightElement,
	Text,
	useColorModeValue
} from '@chakra-ui/react';
import { signIn } from 'next-auth/react'
// Custom components
import { HSeparator } from 'components/separator/Separator';
import DefaultAuthLayout from 'layouts/auth/Default';
// Assets
import Link from 'next/link';
import { FaGithub, FaGoogle } from 'react-icons/fa';
import { MdOutlineRemoveRedEye } from 'react-icons/md';
import { RiEyeCloseLine } from 'react-icons/ri';


export default function SignUp() {
	// Chakra color mode
	const textColor = useColorModeValue('navy.700', 'white');
	const textColorSecondary = 'gray.400';
	const textColorDetails = useColorModeValue('navy.700', 'secondaryGray.600');
	const textColorBrand = useColorModeValue('brand.500', 'white');
	const brandStars = useColorModeValue('brand.500', 'brand.400');
	const googleBg = useColorModeValue('secondaryGray.300', 'whiteAlpha.200');
	const googleText = useColorModeValue('navy.700', 'white');
	const googleHover = useColorModeValue({ bg: 'gray.200' }, { bg: 'whiteAlpha.300' });
	const googleActive = useColorModeValue({ bg: 'secondaryGray.300' }, { bg: 'whiteAlpha.200' });
	const githubBg = useColorModeValue('secondaryGray.300', 'whiteAlpha.200');
	const githubText = useColorModeValue('navy.700', 'white');
	const githubHover = useColorModeValue({ bg: 'gray.200' }, { bg: 'whiteAlpha.300' });
	const githubActive = useColorModeValue({ bg: 'secondaryGray.300' }, { bg: 'whiteAlpha.200' });
	const [show, setShow] = React.useState(false);
	const [signInClicked, setSignInClicked] = useState(false);
	const handleClick = () => setShow(!show);

	return (
		<DefaultAuthLayout illustrationBackground={'/img/auth/auth.png'}>
			<Flex
				maxW={{ base: '100%', md: 'max-content' }}
				w='100%'
				mx={{ base: 'auto', lg: '0px' }}
				me='auto'
				h='100%'
				alignItems='start'
				justifyContent='center'
				mb={{ base: '30px', md: '60px' }}
				px={{ base: '25px', md: '0px' }}
				mt={{ base: '40px', md: '14vh' }}
				flexDirection='column'>
				<Box me='auto'>
					<Heading color={textColor} fontSize='36px' mb='10px'>
						Sign Up
					</Heading>
					<Text mb='36px' ms='4px' color={textColorSecondary} fontWeight='400' fontSize='md'>
						Enter your email and password to sign up!
					</Text>
				</Box>
				<Flex
					zIndex='2'
					direction='column'
					w={{ base: '100%', md: '420px' }}
					maxW='100%'
					background='transparent'
					borderRadius='15px'
					mx={{ base: 'auto', lg: 'unset' }}
					me='auto'
					mb={{ base: '20px', md: 'auto' }}>
					<Button
						fontSize='sm'
						me='0px'
						mb='26px'
						py='15px'
						h='50px'
						borderRadius='16px'
						bgColor={googleBg}
						color={googleText}
						fontWeight='500'
						_hover={googleHover}
						_active={googleActive}
						_focus={googleActive}
						disabled={signInClicked}
						onClick={() => {
							setSignInClicked(true);
							signIn('google');
						}}>
						<div>
							<Icon as={FaGoogle} w='20px' h='20px' me='10px' />
							<p>Sign Up with Google</p>
						</div>
					</Button>
					<Button
						fontSize='sm'
						me='0px'
						mb='26px'
						py='15px'
						h='50px'
						borderRadius='16px'
						bgColor={githubBg}
						color={githubText}
						fontWeight='500'
						_hover={githubHover}
						_active={githubActive}
						_focus={githubActive}
						disabled={signInClicked}
						onClick={() => {
							setSignInClicked(true);
							signIn('github');
						}}>
						<div>
							<Icon as={FaGithub} w='20px' h='20px' me='10px' />
							<p>Sign Up with GitHub</p>
						</div>
					</Button>
					<Flex align='center' mb='25px'>
						<HSeparator />
						<Text color='gray.400' mx='14px'>
							or
						</Text>
						<HSeparator />
					</Flex>
					<FormControl>
						<FormLabel display='flex' ms='4px' fontSize='sm' fontWeight='500' color={textColor} mb='8px'>
							Email<Text color={brandStars}>*</Text>
						</FormLabel>
						<Input
							isRequired={true}
							variant='auth'
							fontSize='sm'
							ms={{ base: '0px', md: '0px' }}
							type='email'
							placeholder='mail@simmmple.com'
							mb='24px'
							fontWeight='500'
							size='lg'
						/>
						<FormLabel ms='4px' fontSize='sm' fontWeight='500' color={textColor} display='flex'>
							Password<Text color={brandStars}>*</Text>
						</FormLabel>
						<InputGroup size='md'>
							<Input
								isRequired={true}
								fontSize='sm'
								placeholder='Min. 8 characters'
								mb='24px'
								size='lg'
								type={show ? 'text' : 'password'}
								variant='auth'
							/>
							<InputRightElement display='flex' alignItems='center' mt='4px'>
								<Icon
									color={textColorSecondary}
									_hover={{ cursor: 'pointer' }}
									as={show ? RiEyeCloseLine : MdOutlineRemoveRedEye}
									onClick={handleClick}
								/>
							</InputRightElement>
						</InputGroup>
						<Flex justifyContent='space-between' align='center' mb='24px'>
							<FormControl display='flex' alignItems='center'>
								<Checkbox id='remember-login' colorScheme='brandScheme' me='10px' />
								<FormLabel
									htmlFor='remember-login'
									mb='0'
									fontWeight='normal'
									color={textColor}
									fontSize='sm'>
									Keep me logged in
								</FormLabel>
							</FormControl>
							<Link href='/auth/forgot-password'>
								<a>
									<Text color={textColorBrand} fontSize='sm' w='124px' fontWeight='500'>
										Forgot password?
									</Text>
								</a>
							</Link>
						</Flex>
						<Button onSubmit={signIn('email')} fontSize='sm' variant='brand' fontWeight='500' w='100%' h='50' mb='24px'>
							Sign Up
						</Button>
					</FormControl>
					<Flex flexDirection='column' justifyContent='center' alignItems='start' maxW='100%' mt='0px'>
						<Text color={textColorDetails} fontWeight='400' fontSize='14px'>
							Already registered?
							<Link href='/auth/sign-in'>
								<a>
									<Text color={textColorBrand} as='span' ms='5px' fontWeight='500'>
										Log in
									</Text>
								</a>
							</Link>
						</Text>
					</Flex>
				</Flex>
			</Flex>
		</DefaultAuthLayout>
	);
}

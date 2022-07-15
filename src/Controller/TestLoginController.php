<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Form\LoginType;
use App\Repository\ClientRepository;
use App\Service\ApiAuthService;
use GuzzleHttp\Client;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\HttpFoundation\Request;

class TestLoginController extends AbstractController
{
    #[Route('/oauth/login', name: 'oauth_login')]
    public function index( Request $request, ClientRepository $clientRepository ): Response
    {
        $client_id = $this->getParameter('app.client_id');

        $success = false;
        
        $existingClientId = $clientRepository->find($client_id);
        $existClientId = $existingClientId->getIdentifier() == $client_id;
        $form = $this->createForm(LoginType::class);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $success = $form->getData();

            if ($success) {
                return $this->redirectToRoute('list');
            } else {
                return $this->redirectToRoute('login');
            }
        }

        return $this->render('security/index.html.twig',[
            'form' => $form->createView(),
            'client_id' => $client_id,
            'exist_client' => $existClientId
        ]);
    }
}
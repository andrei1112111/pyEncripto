from modules import logic
from io import BytesIO
import pygame

import pyEncripto


try:
    USED_PYENCRIPTO
    print("PYENCRIPTO detected!")
except NameError:
    USED_PYENCRIPTO = False


def main():
    pygame.init()
    screen = pygame.display.set_mode((400, 300))
    
    # Загружаем и масштабируем героя
    if USED_PYENCRIPTO:
        raw_image = pygame.image.load(pyEncripto.data_reader["hero.png"]).convert_alpha()
    else:
        raw_image = pygame.image.load("assets/hero.png").convert_alpha()
    hero = pygame.transform.scale(raw_image, (64, 64))
    
    clock = pygame.time.Clock()

    # Позиция героя
    hero_x, hero_y = 100, 100
    speed = 5

    running = True
    while running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False

        keys = pygame.key.get_pressed()
        if keys[pygame.K_w]: hero_y -= speed
        if keys[pygame.K_s]: hero_y += speed
        if keys[pygame.K_a]: hero_x -= speed
        if keys[pygame.K_d]: hero_x += speed

        if keys[pygame.K_ESCAPE]: running = False

        screen.fill((30, 30, 30))
        screen.blit(hero, (hero_x, hero_y))
        pygame.display.flip()
        clock.tick(60)

    pygame.quit()

if __name__ == "__main__":
    main()
